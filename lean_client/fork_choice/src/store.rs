use std::collections::{HashMap, HashSet};

use anyhow::{Result, anyhow, ensure};
use containers::{
    AggregatedSignatureProof, Attestation, AttestationData, Block, BlockHeader, Checkpoint, Config,
    SignatureKey, SignedAggregatedAttestation, SignedAttestation, SignedBlock, Slot, State,
};
use metrics::{METRICS, set_gauge_u64};
use ssz::{H256, SszHash};
use tracing::warn;
use xmss::Signature;

pub type Interval = u64;
pub const INTERVALS_PER_SLOT: Interval = 5;
pub const SECONDS_PER_SLOT: u64 = 4;
/// Milliseconds per interval: (4 * 1000) / 5 = 800ms
/// Using milliseconds avoids integer division truncation (4/5 = 0 in integer math)
pub const MILLIS_PER_INTERVAL: u64 = (SECONDS_PER_SLOT * 1000) / INTERVALS_PER_SLOT;

/// Forkchoice store tracking chain state and validator attestations

#[derive(Debug, Clone, Default)]
pub struct Store {
    pub time: Interval,

    pub config: Config,

    /// Whether this node performs aggregation duties.
    /// Only aggregators import and store individual gossip attestation signatures.
    /// Non-aggregators validate attestation data but drop signatures immediately.
    /// Per leanSpec: subnet filtering is at the p2p layer; this flag is the store-layer gate.
    pub is_aggregator: bool,

    pub head: H256,

    pub safe_target: H256,

    pub latest_justified: Checkpoint,

    pub latest_finalized: Checkpoint,

    /// Set to `true` the first time `on_block` drives a justified checkpoint
    /// update beyond the initial checkpoint-sync value. Validator duties must
    /// not run while this is `false` — the node has not yet observed real
    /// justification progress and its attestations would reference a stale source.
    pub justified_ever_updated: bool,

    /// Set to `true` the first time `on_block` drives a finalized checkpoint
    /// update beyond the initial anchor value.
    ///
    /// The `/states/finalized` endpoint must return 503 while this is `false`.
    /// A checkpoint-synced node that has not yet seen real finalization holds
    /// the anchor block (head slot, not finalized slot) as `latest_finalized`.
    /// Serving that state poisons downstream checkpoint syncs: the receiving
    /// node anchors at the head slot, which exceeds the network's justified
    /// slot, causing the justified-ever-updated gate to never fire.
    pub finalized_ever_updated: bool,

    pub blocks: HashMap<H256, Block>,

    pub states: HashMap<H256, State>,

    pub latest_known_attestations: HashMap<u64, AttestationData>,

    pub latest_new_attestations: HashMap<u64, AttestationData>,

    pub gossip_signatures: HashMap<SignatureKey, Signature>,

    /// Aggregated signature proofs from block bodies (on-chain).
    /// These are attestations that have been included in blocks and are part of
    /// the "known" pool for safe target computation.
    /// Keyed by attestation data root (H256).
    pub latest_known_aggregated_payloads: HashMap<H256, Vec<AggregatedSignatureProof>>,

    /// Aggregated signature proofs from gossip aggregation topic.
    /// These are newly received aggregations that haven't been migrated to "known" yet.
    /// At interval 3, we merge this with latest_known_aggregated_payloads for safe target.
    /// Keyed by attestation data root (H256).
    pub latest_new_aggregated_payloads: HashMap<H256, Vec<AggregatedSignatureProof>>,

    /// Attestation data indexed by hash (data_root).
    /// Used to look up the exact attestation data that was signed when
    /// processing aggregated payloads for safe target computation.
    pub attestation_data_by_root: HashMap<H256, AttestationData>,

    /// Gossip attestations waiting for referenced blocks to arrive.
    /// Keyed by the missing block root. Drained when that block is processed.
    pub pending_attestations: HashMap<H256, Vec<SignedAttestation>>,

    /// Aggregated attestations waiting for referenced blocks to arrive.
    /// Keyed by the missing block root. Drained when that block is processed.
    pub pending_aggregated_attestations: HashMap<H256, Vec<SignedAggregatedAttestation>>,

    /// Block roots that were referenced by attestations but not found in the store.
    /// Drained by the caller (main.rs) to trigger blocks-by-root RPC fetches.
    pub pending_fetch_roots: HashSet<H256>,
}

const JUSTIFICATION_LOOKBACK_SLOTS: u64 = 3;

/// Number of slots before the finalized slot for which states are retained.
/// States older than (finalized_slot - STATE_PRUNE_BUFFER) are pruned after
/// each finalization advance. The buffer covers late-arriving blocks and rapid
/// finalization jumps without risk of evicting a parent state still needed
/// for an in-flight state transition.
pub const STATE_PRUNE_BUFFER: u64 = 128;

impl Store {
    pub fn produce_attestation_data(&self, slot: Slot) -> Result<AttestationData> {
        let head_checkpoint = Checkpoint {
            root: self.head,
            slot: self
                .blocks
                .get(&self.head)
                .ok_or(anyhow!("head block is not known"))?
                .slot,
        };

        let target_checkpoint = self.get_attestation_target();

        Ok(AttestationData {
            slot,
            head: head_checkpoint,
            target: target_checkpoint,
            source: self.latest_justified.clone(),
        })
    }

    pub fn get_attestation_target(&self) -> Checkpoint {
        let mut target = self.head;

        let safe_slot = self.blocks[&self.safe_target].slot;

        // Walk back toward safe target
        for _ in 0..JUSTIFICATION_LOOKBACK_SLOTS {
            if self.blocks[&target].slot > safe_slot {
                target = self.blocks[&target].parent_root;
            } else {
                break;
            }
        }

        let final_slot = self.latest_finalized.slot;
        while !self.blocks[&target].slot.is_justifiable_after(final_slot) {
            target = self.blocks[&target].parent_root;
        }

        let block_target = &self.blocks[&target];
        Checkpoint {
            root: target,
            slot: block_target.slot,
        }
    }

    pub fn compute_block_weights(&self) -> HashMap<H256, i64> {
        let attestations = extract_attestations_from_aggregated_payloads(
            &self.latest_known_aggregated_payloads,
            &self.attestation_data_by_root,
        );

        let start_slot = self.latest_finalized.slot;
        let mut weights: HashMap<H256, i64> = HashMap::new();

        for attestation_data in attestations.values() {
            let mut current_root = attestation_data.head.root;

            while let Some(block) = self.blocks.get(&current_root) {
                if block.slot <= start_slot {
                    break;
                }
                *weights.entry(current_root).or_insert(0) += 1;
                current_root = block.parent_root;
            }
        }

        weights
    }
}

/// Initialize forkchoice store from an anchor state and block
pub fn get_forkchoice_store(
    anchor_state: State,
    anchor_block: SignedBlock,
    config: Config,
    is_aggregator: bool,
) -> Store {
    // Extract the plain Block from the signed block
    let block = anchor_block.block.clone();
    let block_slot = block.slot;

    // Compute block root differently for genesis vs checkpoint sync:
    // - Genesis (slot 0): Use block.hash_tree_root() directly — block and state are consistent.
    // - Checkpoint sync (slot > 0): Reconstruct BlockHeader from state.latest_block_header,
    //   using anchor_state.hash_tree_root() as state_root.  This guarantees the root stored
    //   as the key in store.blocks / store.states is the canonical one committed to by the
    //   downloaded state, independent of what the real block's state_root field contains.
    let block_root = if block_slot.0 == 0 {
        block.hash_tree_root()
    } else {
        let block_header = BlockHeader {
            slot: anchor_state.latest_block_header.slot,
            proposer_index: anchor_state.latest_block_header.proposer_index,
            parent_root: anchor_state.latest_block_header.parent_root,
            state_root: anchor_state.hash_tree_root(),
            body_root: anchor_state.latest_block_header.body_root,
        };
        block_header.hash_tree_root()
    };

    // Substitute anchor_root for the checkpoint roots (the historical
    // justified/finalized blocks are not in our store), but keep the actual
    // slots from the downloaded state.  validate_attestation_data skips
    // the block-slot match when the source root is a known checkpoint.
    let latest_justified = Checkpoint {
        root: block_root,
        slot: anchor_state.latest_justified.slot,
    };

    let latest_finalized = Checkpoint {
        root: block_root,
        slot: anchor_state.latest_finalized.slot,
    };

    // Store the original anchor_state - do NOT modify it
    // Modifying checkpoints would change its hash_tree_root(), breaking the
    // consistency with block.state_root
    Store {
        time: block_slot.0 * INTERVALS_PER_SLOT,
        config,
        is_aggregator,
        head: block_root,
        safe_target: block_root,
        latest_justified,
        latest_finalized,
        justified_ever_updated: block_slot.0 == 0,
        finalized_ever_updated: false,
        blocks: {
            let mut m = HashMap::new();
            m.insert(block_root, block);
            m
        },
        states: {
            let mut m = HashMap::new();
            m.insert(block_root, anchor_state);
            m
        },
        latest_known_attestations: HashMap::new(),
        latest_new_attestations: HashMap::new(),
        gossip_signatures: HashMap::new(),
        latest_known_aggregated_payloads: HashMap::new(),
        latest_new_aggregated_payloads: HashMap::new(),
        attestation_data_by_root: HashMap::new(),
        pending_attestations: HashMap::new(),
        pending_aggregated_attestations: HashMap::new(),
        pending_fetch_roots: HashSet::new(),
    }
}

pub fn get_fork_choice_head(
    store: &Store,
    mut root: H256,
    latest_attestations: &HashMap<u64, AttestationData>,
    min_votes: usize,
) -> H256 {
    if root.is_zero() {
        root = store
            .blocks
            .iter()
            .min_by_key(|(_, block)| block.slot)
            .map(|(r, _)| *r)
            .expect("Error: Empty block.");
    }
    let mut vote_weights: HashMap<H256, usize> = HashMap::new();
    let root_slot = match store.blocks.get(&root) {
        Some(block) => block.slot,
        None => {
            warn!(
                %root,
                justified_slot = store.latest_justified.slot.0,
                "justified root not in store blocks, returning justified root as head"
            );
            return root;
        }
    };

    // stage 1: accumulate weights by walking up from each attestation's head
    for attestation_data in latest_attestations.values() {
        let mut curr = attestation_data.head.root;

        if let Some(block) = store.blocks.get(&curr) {
            let mut curr_slot = block.slot;

            while curr_slot > root_slot {
                *vote_weights.entry(curr).or_insert(0) += 1;

                if let Some(parent_block) = store.blocks.get(&curr) {
                    curr = parent_block.parent_root;
                    if curr.is_zero() {
                        break;
                    }
                    if let Some(next_block) = store.blocks.get(&curr) {
                        curr_slot = next_block.slot;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
    }

    // stage 2: build adjacency tree (parent -> children)
    let mut child_map: HashMap<H256, Vec<H256>> = HashMap::new();
    for (block_hash, block) in &store.blocks {
        if !block.parent_root.is_zero() {
            if vote_weights.get(block_hash).copied().unwrap_or(0) >= min_votes {
                child_map
                    .entry(block.parent_root)
                    .or_default()
                    .push(*block_hash);
            }
        }
    }

    // stage 3: greedy walk choosing heaviest child at each fork
    let mut curr = root;
    loop {
        let children = match child_map.get(&curr) {
            Some(list) if !list.is_empty() => list,
            _ => return curr,
        };

        // Choose best child: most attestations, then lexicographically highest hash
        curr = *children
            .iter()
            .max_by(|&&a, &&b| {
                let wa = vote_weights.get(&a).copied().unwrap_or(0);
                let wb = vote_weights.get(&b).copied().unwrap_or(0);
                wa.cmp(&wb).then_with(|| a.cmp(&b))
            })
            .unwrap();
    }
}

pub fn get_latest_justified(states: &HashMap<H256, State>) -> Option<&Checkpoint> {
    states
        .values()
        .map(|state| &state.latest_justified)
        .max_by_key(|checkpoint| checkpoint.slot)
}

pub fn update_head(store: &mut Store) {
    let old_head = store.head;

    // Compute new head using LMD-GHOST from latest justified root
    let new_head = get_fork_choice_head(
        store,
        store.latest_justified.root,
        &store.latest_known_attestations,
        0,
    );
    store.head = new_head;

    // Detect reorg if head changed and new head's parent is not old head
    if new_head != old_head && !old_head.is_zero() {
        if let Some(new_head_block) = store.blocks.get(&new_head) {
            if new_head_block.parent_root != old_head {
                let mut depth = 0u64;
                let mut current = old_head;

                while !current.is_zero() && depth < 100 {
                    if let Some(block) = store.blocks.get(&current) {
                        // Check if new head descends from this block
                        let mut check = new_head;
                        while !check.is_zero() {
                            if check == current {
                                // Found common ancestor
                                break;
                            }
                            if let Some(b) = store.blocks.get(&check) {
                                check = b.parent_root;
                            } else {
                                break;
                            }
                        }
                        if check == current {
                            break;
                        }
                        depth += 1;
                        current = block.parent_root;
                    } else {
                        break;
                    }
                }

                // Record reorg metrics
                METRICS.get().map(|metrics| {
                    metrics.lean_fork_choice_reorgs_total.inc();
                    metrics.lean_fork_choice_reorg_depth.observe(depth as f64);
                });
            }
        }
    }

    set_gauge_u64(
        |m| &m.lean_head_slot,
        || {
            let head = store
                .blocks
                .get(&new_head)
                .ok_or(anyhow!("failed to get head block"))?;

            Ok(head.slot.0)
        },
    );
}

/// Extract per-validator attestations from aggregated payloads.
///
/// Walks through all aggregated proofs and extracts the latest attestation
/// data for each validator based on their participation bits.
fn extract_attestations_from_aggregated_payloads(
    payloads: &HashMap<H256, Vec<AggregatedSignatureProof>>,
    attestation_data_by_root: &HashMap<H256, AttestationData>,
) -> HashMap<u64, AttestationData> {
    let mut attestations: HashMap<u64, AttestationData> = HashMap::new();

    for (data_root, proofs) in payloads {
        // Look up the attestation data for this data root
        let Some(attestation_data) = attestation_data_by_root.get(data_root) else {
            continue;
        };

        // For each proof, extract participating validators
        for proof in proofs {
            for (bit_idx, bit) in proof.participants.0.iter().enumerate() {
                if *bit {
                    let validator_id = bit_idx as u64;
                    // Only update if this is a newer attestation for this validator
                    if attestations
                        .get(&validator_id)
                        .map_or(true, |existing| existing.slot < attestation_data.slot)
                    {
                        attestations.insert(validator_id, attestation_data.clone());
                    }
                }
            }
        }
    }

    attestations
}

/// Update safe target from aggregated attestations.
///
/// Safe target is computed by merging both aggregated payload pools:
/// - latest_known_aggregated_payloads: from block bodies (on-chain)
/// - latest_new_aggregated_payloads: from gossip aggregation topic
///
/// Both pools are merged because at interval 3 (when this runs), the migration
/// to "known" (interval 4) hasn't happened yet.
pub fn update_safe_target(store: &mut Store) {
    let n_validators = if let Some(state) = store.states.get(&store.head) {
        state.validators.len_usize()
    } else {
        0
    };

    // Compute 2/3 supermajority threshold using ceiling division
    // Formula: ceil(2n/3) = (2n + 2) / 3 for integer math
    let min_score = (n_validators * 2 + 2) / 3;
    let root = store.latest_justified.root;

    // Merge both aggregated payload pools to see all attestations
    let mut all_payloads: HashMap<H256, Vec<AggregatedSignatureProof>> =
        store.latest_known_aggregated_payloads.clone();

    for (data_root, proofs) in &store.latest_new_aggregated_payloads {
        all_payloads
            .entry(*data_root)
            .or_default()
            .extend(proofs.clone());
    }

    // Extract per-validator attestations from merged payloads
    let attestations = extract_attestations_from_aggregated_payloads(
        &all_payloads,
        &store.attestation_data_by_root,
    );

    // Run LMD-GHOST with 2/3 threshold to find safe target
    let new_safe_target = get_fork_choice_head(store, root, &attestations, min_score);
    store.safe_target = new_safe_target;

    set_gauge_u64(
        |metrics| &metrics.lean_safe_target_slot,
        || {
            let safe_target = store
                .blocks
                .get(&new_safe_target)
                .ok_or(anyhow!("failed to get safe target block"))?;

            Ok(safe_target.slot.0)
        },
    );
}

pub fn accept_new_attestations(store: &mut Store) {
    store
        .latest_known_attestations
        .extend(store.latest_new_attestations.drain());
    // Promote gossip-received aggregated proofs to the known pool so they
    // are available for block production at the next interval 0.
    for (data_root, proofs) in store.latest_new_aggregated_payloads.drain() {
        store
            .latest_known_aggregated_payloads
            .entry(data_root)
            .or_default()
            .extend(proofs);
    }
    update_head(store);
    METRICS.get().map(|m| {
        m.grandine_fork_choice_known_attestations
            .set(store.latest_known_attestations.len() as i64);
        m.grandine_fork_choice_new_attestations
            .set(store.latest_new_attestations.len() as i64);
    });
}

pub fn tick_interval(store: &mut Store, has_proposal: bool) {
    store.time += 1;
    // Calculate current interval within slot: time % INTERVALS_PER_SLOT
    // 5 intervals per slot (800ms each)
    let curr_interval = store.time % INTERVALS_PER_SLOT;

    match curr_interval {
        0 if has_proposal => accept_new_attestations(store), // Interval 0: Block proposal
        1 => {}                                              // Interval 1: Attestation phase
        2 => {}                         // Interval 2: Aggregation phase (handled in main.rs)
        3 => update_safe_target(store), // Interval 3: Safe target update
        4 => accept_new_attestations(store), // Interval 4: Accept attestations
        _ => {}
    }
}

#[inline]
pub fn get_proposal_head(store: &mut Store, slot: Slot) -> H256 {
    // Convert to milliseconds for on_tick (devnet-3 uses 800ms intervals)
    let slot_time_millis = (store.config.genesis_time + (slot.0 * SECONDS_PER_SLOT)) * 1000;

    crate::handlers::on_tick(store, slot_time_millis, true);
    accept_new_attestations(store);
    store.head
}

pub struct BlockProductionInputs {
    pub slot: Slot,
    pub validator_index: u64,
    pub head_root: H256,
    pub head_state: State,
    pub available_attestations: Vec<Attestation>,
    pub known_block_roots: HashSet<H256>,
    pub gossip_signatures: HashMap<SignatureKey, Signature>,
    pub aggregated_payloads: HashMap<H256, Vec<AggregatedSignatureProof>>,
    pub log_inv_rate: usize,
    pub store_latest_justified: Checkpoint,
}

pub fn prepare_block_production(
    store: &mut Store,
    slot: Slot,
    validator_index: u64,
    log_inv_rate: usize,
) -> Result<BlockProductionInputs> {
    let head_root = get_proposal_head(store, slot);
    let head_state = store
        .states
        .get(&head_root)
        .ok_or_else(|| anyhow!("Head state not found"))?
        .clone();

    let num_validators = head_state.validators.len_u64();
    let expected_proposer = slot.0 % num_validators;
    ensure!(
        validator_index == expected_proposer,
        "Validator {} is not the proposer for slot {} (expected {})",
        validator_index,
        slot.0,
        expected_proposer
    );

    // Step 1: individual attestations already tracked per-validator.
    let mut available_attestations: Vec<Attestation> = store
        .latest_known_attestations
        .iter()
        .map(|(validator_idx, attestation_data)| Attestation {
            validator_id: *validator_idx,
            data: attestation_data.clone(),
        })
        .collect();

    // Step 2: synthesize entries for validators that arrived *only* via
    // on_aggregated_attestation.  Those validators have proofs in
    // latest_known_aggregated_payloads but were never inserted into
    // latest_known_attestations, so build_block's fixed-point loop would
    // otherwise silently skip them.
    {
        let known_validators: HashSet<u64> =
            store.latest_known_attestations.keys().copied().collect();
        let mut seen_synthesized: HashSet<(u64, H256)> = HashSet::new();
        for (data_root, proofs) in &store.latest_known_aggregated_payloads {
            if let Some(att_data) = store.attestation_data_by_root.get(data_root) {
                for proof in proofs {
                    for vid in proof.participants.to_validator_indices() {
                        if !known_validators.contains(&vid)
                            && seen_synthesized.insert((vid, *data_root))
                        {
                            available_attestations.push(Attestation {
                                validator_id: vid,
                                data: att_data.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    let known_block_roots: HashSet<H256> = store.blocks.keys().copied().collect();
    let gossip_signatures = store.gossip_signatures.clone();
    let aggregated_payloads = store.latest_known_aggregated_payloads.clone();

    Ok(BlockProductionInputs {
        slot,
        validator_index,
        head_root,
        head_state,
        available_attestations,
        known_block_roots,
        gossip_signatures,
        aggregated_payloads,
        log_inv_rate,
        store_latest_justified: store.latest_justified.clone(),
    })
}

pub fn execute_block_production(
    inputs: BlockProductionInputs,
) -> Result<(H256, Block, Vec<AggregatedSignatureProof>)> {
    let BlockProductionInputs {
        slot,
        validator_index,
        head_root,
        head_state,
        available_attestations,
        known_block_roots,
        gossip_signatures,
        aggregated_payloads,
        log_inv_rate,
        store_latest_justified,
    } = inputs;

    let (final_block, final_post_state, _aggregated_attestations, signatures) = head_state
        .build_block(
            slot,
            validator_index,
            head_root,
            None,
            Some(available_attestations),
            Some(&known_block_roots),
            Some(&gossip_signatures),
            Some(&aggregated_payloads),
            log_inv_rate,
        )?;

    ensure!(
        final_post_state.latest_justified.slot >= store_latest_justified.slot,
        "Produced block justified={} < store justified={}. Fixed-point attestation loop did not converge.",
        final_post_state.latest_justified.slot.0,
        store_latest_justified.slot.0,
    );

    let block_root = final_block.hash_tree_root();

    Ok((block_root, final_block, signatures))
}

pub fn produce_block_with_signatures(
    store: &mut Store,
    slot: Slot,
    validator_index: u64,
    log_inv_rate: usize,
) -> Result<(H256, Block, Vec<AggregatedSignatureProof>)> {
    let inputs = prepare_block_production(store, slot, validator_index, log_inv_rate)?;
    execute_block_production(inputs)
}
