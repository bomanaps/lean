use anyhow::{Result, anyhow, ensure};
use bitvec::{bitvec, order::Lsb0, vec::BitVec};
use metrics::METRICS;
use serde::{Deserialize, Serialize};
use ssz::{BitList, H256, PersistentList, Ssz, SszHash};
use std::collections::{BTreeMap, HashMap, HashSet};
use tracing::{info, trace, warn};
use try_from_iterator::TryFromIterator;
use typenum::{Prod, U262144};
use xmss::{PublicKey, Signature};

use crate::{
    AggregatedSignatureProof, Checkpoint, Config, Slot,
    attestation::{
        AggregatedAttestation, AggregatedAttestations, AggregationBits, AttestationData,
    },
    block::{Block, BlockBody, BlockHeader, SignedBlock},
    validator::{Validator, ValidatorRegistryLimit, Validators},
};

/// Maximum number of distinct AttestationData entries per block (spec: chain/config.py:36).
const MAX_ATTESTATIONS_DATA: usize = 16;

type HistoricalRootsLimit = U262144; // 2^18

type JustificationValidatorsLimit = Prod<ValidatorRegistryLimit, HistoricalRootsLimit>;

pub type HistoricalBlockHashes = PersistentList<H256, U262144>;
pub type JustificationValidators = BitList<JustificationValidatorsLimit>;
pub type JustificationRoots = PersistentList<H256, HistoricalRootsLimit>;

#[derive(Debug, Clone, Serialize, Deserialize, Ssz, Default)]
#[ssz(transparent)]
pub struct JustifiedSlots(
    #[serde(with = "crate::serde_helpers::bitlist")] pub BitList<HistoricalRootsLimit>,
);

impl JustifiedSlots {
    fn is_slot_justified(&self, finalized_slot: Slot, target_slot: Slot) -> Result<bool> {
        let Some(relative_index) = target_slot.justified_index_after(finalized_slot) else {
            return Ok(true);
        };

        self.0
            .get(relative_index as usize)
            .map(|v| *v)
            .ok_or(anyhow!("Slot {target_slot:?} is outside the tracked range"))
    }

    fn with_justified(
        mut self,
        finalized_slot: Slot,
        target_slot: Slot,
        value: bool,
    ) -> Result<Self> {
        let Some(relative_index) = target_slot.justified_index_after(finalized_slot) else {
            return Ok(self);
        };

        self.0
            .get_mut(relative_index as usize)
            .map(|mut bit| bit.set(value))
            .map(|_| self)
            .ok_or(anyhow!("Slot {target_slot:?} is outside the tracked range"))
    }

    fn shift_window(self, delta: u64) -> Self {
        if delta == 0 {
            return self;
        };

        // todo(stf): this probably can be optimized to use something like
        // this. However, BitList::from_bit_box is private, so it is not
        // possible now.
        // let bits = &self.0[(delta as usize)..];

        // Ok(Self(BitList::from_bit_box(
        //     bits.to_bitvec().into_boxed_bitslice(),
        // )))

        let bits = &self.0[(delta as usize)..];
        let mut output = BitList::with_length(bits.len());

        for (i, val) in bits.iter().enumerate() {
            output.set(i, *val);
        }

        Self(output)
    }

    fn extend_to_slot(self, finalized_slot: Slot, target_slot: Slot) -> Self {
        let Some(relative_index) = target_slot.justified_index_after(finalized_slot) else {
            return self;
        };

        let required_capacity = relative_index + 1;
        let Some(gap_size) = required_capacity.checked_sub(self.0.len() as u64) else {
            return self;
        };

        let mut list = BitList::with_length(required_capacity as usize);

        for (index, bit) in self.0.iter().enumerate() {
            list.set(index, *bit);
        }

        Self(list)
    }
}

#[derive(Clone, Debug, Ssz, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    // --- configuration (spec-local) ---
    pub config: Config,

    // --- slot / header tracking ---
    pub slot: Slot,
    pub latest_block_header: BlockHeader,

    // --- fork-choice checkpoints ---
    pub latest_justified: Checkpoint,
    pub latest_finalized: Checkpoint,

    // --- historical data ---
    #[serde(with = "crate::serde_helpers")]
    pub historical_block_hashes: HistoricalBlockHashes,

    // --- flattened justification tracking ---
    pub justified_slots: JustifiedSlots,

    // Validators registry
    #[serde(with = "crate::serde_helpers")]
    pub validators: Validators,

    #[serde(with = "crate::serde_helpers")]
    pub justifications_roots: JustificationRoots,
    #[serde(with = "crate::serde_helpers::bitlist")]
    pub justifications_validators: JustificationValidators,
}

impl State {
    pub fn generate_genesis_with_validators(genesis_time: u64, validators: Vec<Validator>) -> Self {
        let body_for_root = BlockBody {
            attestations: Default::default(),
        };
        let genesis_header = BlockHeader {
            slot: Slot(0),
            proposer_index: 0,
            parent_root: H256::zero(),
            state_root: H256::zero(),
            body_root: body_for_root.hash_tree_root(),
        };

        let mut validator_list = PersistentList::default();
        for v in validators {
            validator_list.push(v).expect("Failed to add validator");
        }

        Self {
            config: Config { genesis_time },
            slot: Slot(0),
            latest_block_header: genesis_header,
            latest_justified: Checkpoint {
                root: H256::zero(),
                slot: Slot(0),
            },
            latest_finalized: Checkpoint {
                root: H256::zero(),
                slot: Slot(0),
            },
            historical_block_hashes: HistoricalBlockHashes::default(),
            justified_slots: JustifiedSlots::default(),
            validators: validator_list,
            justifications_roots: JustificationRoots::default(),
            justifications_validators: JustificationValidators::default(),
        }
    }

    pub fn generate_genesis(genesis_time: u64, num_validators: u64) -> Self {
        let body_for_root = BlockBody {
            attestations: Default::default(),
        };
        let header = BlockHeader {
            slot: Slot(0),
            proposer_index: 0,
            parent_root: H256::zero(),
            state_root: H256::zero(),
            body_root: body_for_root.hash_tree_root(),
        };

        //TEMP: Create validators list with dummy validators
        let mut validators = PersistentList::default();
        for i in 0..num_validators {
            let validator = Validator {
                attestation_pubkey: PublicKey::default(),
                proposal_pubkey: PublicKey::default(),
                index: i,
            };
            validators.push(validator).expect("Failed to add validator");
        }

        Self {
            config: Config { genesis_time },
            slot: Slot(0),
            latest_block_header: header,
            latest_justified: Checkpoint {
                root: H256::zero(),
                slot: Slot(0),
            },
            latest_finalized: Checkpoint {
                root: H256::zero(),
                slot: Slot(0),
            },
            historical_block_hashes: HistoricalBlockHashes::default(),
            justified_slots: JustifiedSlots::default(),
            validators,
            justifications_roots: JustificationRoots::default(),
            justifications_validators: JustificationValidators::default(),
        }
    }

    pub fn get_justifications(&self) -> BTreeMap<H256, Vec<bool>> {
        let num_validators = self.validators.len_usize();
        (&self.justifications_roots)
            .into_iter()
            .enumerate()
            .map(|(i, root)| {
                let start = i * num_validators;
                let end = start + num_validators;
                // Extract bits from BitList for this root's validator votes
                let votes: Vec<bool> = (start..end)
                    .map(|idx| {
                        self.justifications_validators
                            .get(idx)
                            .map(|b| *b)
                            .unwrap_or(false)
                    })
                    .collect();
                (*root, votes)
            })
            .collect()
    }

    pub fn with_justifications(mut self, map: BTreeMap<H256, Vec<bool>>) -> Self {
        let num_validators = self.validators.len_usize();
        let mut roots: Vec<_> = map.keys().cloned().collect();
        roots.sort();

        // Build PersistentList by pushing elements
        let mut new_roots = JustificationRoots::default();
        for r in &roots {
            new_roots.push(*r).expect("within limit");
        }

        // Build BitList: create with length, then set bits
        let total_bits = roots.len() * num_validators;
        let mut new_validators = JustificationValidators::new(false, total_bits);

        for (i, r) in roots.iter().enumerate() {
            let v = map.get(r).expect("root present");
            assert_eq!(
                v.len(),
                num_validators,
                "vote vector must match validator count"
            );
            let base = i * num_validators;
            for (j, &bit) in v.iter().enumerate() {
                if bit {
                    new_validators.set(base + j, true);
                }
            }
        }

        self.justifications_roots = new_roots;
        self.justifications_validators = new_validators;
        self
    }

    pub fn with_historical_hashes(mut self, hashes: Vec<H256>) -> Self {
        let mut new_hashes = HistoricalBlockHashes::default();
        for h in hashes {
            new_hashes.push(h).expect("within limit");
        }
        self.historical_block_hashes = new_hashes;
        self
    }

    pub fn state_transition(
        &self,
        signed_block: SignedBlock,
        valid_signatures: bool,
    ) -> Result<Self> {
        ensure!(valid_signatures, "invalid block signatures");

        let _timer = METRICS
            .get()
            .map(|metrics| metrics.lean_state_transition_time_seconds.start_timer());
        let block = &signed_block.block;
        let mut state = self.process_slots(block.slot)?;
        state = state.process_block(block)?;

        let state_root = state.hash_tree_root();

        ensure!(
            block.state_root == state_root,
            "invalid block state root (block.state_root={}, actual={state_root})",
            block.state_root
        );

        Ok(state)
    }

    pub fn process_slots(&self, target_slot: Slot) -> Result<Self> {
        ensure!(self.slot < target_slot, "target slot must be in the future");

        let _timer = METRICS.get().map(|metrics| {
            metrics
                .lean_state_transition_slots_processing_time_seconds
                .start_timer()
        });

        let mut state = self.clone();

        while state.slot < target_slot {
            if state.latest_block_header.state_root.is_zero() {
                state.latest_block_header.state_root = state.hash_tree_root();
            }
            state.slot = Slot(state.slot.0 + 1);

            METRICS
                .get()
                .map(|metrics| metrics.lean_state_transition_slots_processed_total.inc());
        }

        Ok(state)
    }

    pub fn process_block(self, block: &Block) -> Result<Self> {
        let _timer = METRICS.get().map(|metrics| {
            metrics
                .lean_state_transition_block_processing_time_seconds
                .start_timer()
        });

        let state = self.process_block_header(block)?;

        state.process_attestations(&block.body.attestations)
    }

    pub fn process_block_header(mut self, block: &Block) -> Result<Self> {
        let parent_header = self.latest_block_header;
        let parent_root = parent_header.hash_tree_root();

        ensure!(block.slot == self.slot, "Block slot mismatch");

        ensure!(
            block.slot > parent_header.slot,
            "Block is older than latest header"
        );

        ensure!(
            is_proposer_for(block.proposer_index, self.slot, self.validators.len_u64()),
            "Incorrect block proposer"
        );

        ensure!(
            block.parent_root == parent_root,
            "Block parent root mismatch"
        );

        let is_genesis_parent = parent_header.slot.0 == 0;

        let (new_latest_justified, new_latest_finalized) = if is_genesis_parent {
            (
                Checkpoint {
                    root: parent_root,
                    slot: Slot(0),
                },
                Checkpoint {
                    root: parent_root,
                    slot: Slot(0),
                },
            )
        } else {
            (self.latest_justified.clone(), self.latest_finalized.clone())
        };

        let num_empty_slots = block.slot.0 - parent_header.slot.0 - 1;

        self.historical_block_hashes.push(parent_root)?;
        for _ in 0..num_empty_slots {
            self.historical_block_hashes.push(H256::zero())?;
        }

        let last_materialized_slot = block.slot.0 - 1;
        self.justified_slots = self
            .justified_slots
            .extend_to_slot(self.latest_finalized.slot, Slot(last_materialized_slot));

        let new_header = BlockHeader {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            body_root: block.body.hash_tree_root(),
            state_root: H256::zero(),
        };

        self.latest_justified = new_latest_justified;
        self.latest_finalized = new_latest_finalized;
        self.latest_block_header = new_header;
        Ok(self)
    }

    pub fn process_attestations(&self, attestations: &AggregatedAttestations) -> Result<Self> {
        let _timer = METRICS.get().map(|metrics| {
            metrics
                .lean_state_transition_attestations_processing_time_seconds
                .start_timer()
        });

        ensure!(
            self.justifications_roots
                .into_iter()
                .all(|root| !root.is_zero()),
            "zero hash is not allowed in justification roots"
        );

        let mut justifications = self
            .justifications_roots
            .into_iter()
            .enumerate()
            .map(|(i, root)| {
                (
                    root.clone(),
                    self.justifications_validators
                        [i * self.validators.len_usize()..(i + 1) * self.validators.len_usize()]
                        .to_bitvec(),
                )
            })
            .collect::<HashMap<_, BitVec<u8>>>();

        let mut latest_justified = self.latest_justified.clone();
        let mut latest_finalized = self.latest_finalized.clone();
        let mut finalized_slot = latest_finalized.slot;
        let mut justified_slots = self.justified_slots.clone();

        let mut root_to_slot = HashMap::new();
        let start_slot = finalized_slot.0 + 1;
        let end_slot = self.historical_block_hashes.len_u64();
        for i in start_slot..end_slot {
            let root = self.historical_block_hashes.get(i)?;

            root_to_slot
                .entry(root.clone())
                .and_modify(|slot: &mut Slot| {
                    if i > slot.0 {
                        *slot = Slot(i);
                    }
                })
                .or_insert(Slot(i));
        }

        for attestation in attestations {
            METRICS.get().map(|metrics| {
                metrics
                    .lean_state_transition_attestations_processed_total
                    .inc()
            });

            let source = attestation.data.source.clone();
            let target = attestation.data.target.clone();

            if !justified_slots.is_slot_justified(finalized_slot, source.slot)? {
                info!("skipping attestation, source slot is not justified");
                continue;
            }

            if justified_slots.is_slot_justified(finalized_slot, target.slot)? {
                info!("skipping attestation, target slot is already justified");
                continue;
            }

            if source.root.is_zero() || target.root.is_zero() {
                info!("skipping attestation, source or target slots are zero");
                continue;
            }

            if &source.root != self.historical_block_hashes.get(source.slot.0)?
                || &target.root != self.historical_block_hashes.get(target.slot.0)?
            {
                info!(
                    "skipping attestation, source or target roots not found in historical block hashes"
                );
                continue;
            }

            if target.slot <= source.slot {
                info!("skipping attestation, target slot is before source slot");
                continue;
            }

            if !target.slot.is_justifiable_after(finalized_slot) {
                info!("skipping attestation, target slot is not yet justifiable");
                continue;
            }

            if !justifications.contains_key(&target.root) {
                justifications.insert(
                    target.root.clone(),
                    bitvec![u8, Lsb0; 0; self.validators.len_usize()],
                );
            }

            for validator_id in attestation.aggregation_bits.to_validator_indices() {
                let mut vote = justifications
                    .get_mut(&target.root)
                    .ok_or(anyhow!("unknown target root"))?
                    .get_mut(validator_id as usize)
                    .ok_or(anyhow!("validator index is out of range"))?;

                vote.set(true);
            }

            let count = justifications[&target.root]
                .iter()
                .map(|v| *v as u64)
                .sum::<u64>();

            if 3 * count >= 2 * self.validators.len_u64() {
                info!("justifying slot {target:?}");
                latest_justified = target.clone();
                justified_slots =
                    justified_slots.with_justified(finalized_slot, target.slot, true)?;

                justifications.remove(&target.root);

                if !(source.slot.0 + 1..target.slot.0)
                    .any(|slot| Slot(slot).is_justifiable_after(finalized_slot))
                {
                    info!("finalizing {source:?}");
                    let old_finalized_slot = finalized_slot;
                    latest_finalized = source;
                    finalized_slot = latest_finalized.slot;

                    // Record successful finalization
                    METRICS.get().map(|metrics| {
                        metrics
                            .lean_finalizations_total
                            .with_label_values(&["success"])
                            .inc();
                    });
                    let delta = finalized_slot.0.checked_sub(old_finalized_slot.0);

                    if let Some(delta) = delta
                        && delta > 0
                    {
                        justified_slots = justified_slots.shift_window(delta);

                        ensure!(
                            justifications
                                .keys()
                                .all(|root| root_to_slot.contains_key(root)),
                            "Justification root missing from root_to_slot"
                        );
                        justifications.retain(|root, _| root_to_slot[root].0 > finalized_slot.0);
                    }
                }
                // justified_slots = justified_slots
            }
        }

        let sorted_roots = {
            let mut roots = justifications.keys().copied().collect::<Vec<_>>();
            roots.sort();
            roots
        };

        let mut output = self.clone();
        output.justifications_roots = JustificationRoots::try_from_iter(sorted_roots.clone())?;

        // TODO(stf): this can be optimized by using something like concatenate.
        // However, currently not possible as BitList doesn't allow constructing
        // from structure.
        output.justifications_validators = {
            let bits = sorted_roots
                .iter()
                .flat_map(|root| justifications[root].clone())
                .collect::<Vec<_>>();

            let mut output = BitList::with_length(bits.len());

            for (i, val) in bits.into_iter().enumerate() {
                output.set(i, val);
            }

            output
        };

        output.justified_slots = justified_slots;
        output.latest_justified = latest_justified;
        output.latest_finalized = latest_finalized;

        Ok(output)
    }

    /// Build a valid block on top of this state.
    ///
    /// Iterates over `aggregated_payloads` keyed by `data_root` (with the
    /// AttestationData carried in the value), applies the spec's fixed-point
    /// attestation selection: sort by `target.slot`, admit entries whose
    /// `head.root` is known and whose `source` matches the current justified
    /// checkpoint, greedily select proofs maximizing validator coverage, run
    /// the STF, and repeat as long as the post-state's justified checkpoint
    /// advances. Caps distinct AttestationData entries at MAX_ATTESTATIONS_DATA.
    ///
    /// Aggregator-published proofs are the sole input — no gossip-time
    /// re-aggregation at proposal. Matches leanSpec build_block, ethlambda's
    /// blockchain::store::build_block, and zeam's getProposalAttestations.
    pub fn build_block(
        &self,
        slot: Slot,
        proposer_index: u64,
        parent_root: H256,
        known_block_roots: &HashSet<H256>,
        aggregated_payloads: &HashMap<H256, (AttestationData, Vec<AggregatedSignatureProof>)>,
        log_inv_rate: usize,
    ) -> Result<(
        Block,
        Self,
        Vec<AggregatedAttestation>,
        Vec<AggregatedSignatureProof>,
    )> {
        let mut selected: Vec<(AggregatedAttestation, AggregatedSignatureProof)> = Vec::new();

        if !aggregated_payloads.is_empty() {
            // Genesis edge case: process_block_header rebinds latest_justified.root
            // to parent_root when building on slot 0. Apply the same derivation
            // here so attestation sources match.
            let mut current_justified = if self.latest_block_header.slot == Slot(0) {
                Checkpoint {
                    root: parent_root,
                    slot: self.latest_justified.slot,
                }
            } else {
                self.latest_justified.clone()
            };

            // Sort by target.slot for deterministic processing order.
            let mut sorted_entries: Vec<(&H256, &(AttestationData, Vec<AggregatedSignatureProof>))> =
                aggregated_payloads.iter().collect();
            sorted_entries.sort_by_key(|(_, (data, _))| data.target.slot);

            let mut processed_data_roots: HashSet<H256> = HashSet::new();

            loop {
                let mut found_new = false;

                for &(data_root, (att_data, proofs)) in &sorted_entries {
                    if processed_data_roots.contains(data_root) {
                        continue;
                    }
                    if processed_data_roots.len() >= MAX_ATTESTATIONS_DATA {
                        break;
                    }
                    if !known_block_roots.contains(&att_data.head.root) {
                        continue;
                    }
                    if att_data.source != current_justified {
                        continue;
                    }

                    processed_data_roots.insert(*data_root);
                    found_new = true;

                    let indices = AggregatedSignatureProof::select_greedily(proofs);
                    for idx in indices {
                        let proof = proofs[idx].clone();
                        selected.push((
                            AggregatedAttestation {
                                aggregation_bits: proof.participants.clone(),
                                data: att_data.clone(),
                            },
                            proof,
                        ));
                    }
                }

                if !found_new {
                    break;
                }

                // Run STF on a candidate block to see if justification advanced.
                let candidate_attestations = AggregatedAttestations::try_from_iter(
                    selected.iter().map(|(att, _)| att.clone()),
                )?;
                let candidate_block = Block {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root: H256::zero(),
                    body: BlockBody {
                        attestations: candidate_attestations,
                    },
                };
                let post_state = self.process_slots(slot)?.process_block(&candidate_block)?;

                if post_state.latest_justified != current_justified {
                    current_justified = post_state.latest_justified;
                } else {
                    break;
                }
            }
        }

        // Compact: merge proofs sharing the same AttestationData via recursive
        // aggregation so each AttestationData appears at most once in the body.
        let compacted = self.compact_proofs_by_data(selected, log_inv_rate)?;

        METRICS.get().map(|metrics| {
            metrics
                .lean_pq_sig_attestations_in_aggregated_signatures_total
                .inc_by(
                    compacted
                        .iter()
                        .map(|(att, _)| att.aggregation_bits.to_validator_indices().len())
                        .sum::<usize>() as u64,
                );
        });

        let (aggregated_attestations, aggregated_signatures): (Vec<_>, Vec<_>) =
            compacted.into_iter().unzip();

        let mut final_block = Block {
            slot,
            proposer_index,
            parent_root,
            state_root: H256::zero(),
            body: BlockBody {
                attestations: AggregatedAttestations::try_from_iter(
                    aggregated_attestations.iter().cloned(),
                )?,
            },
        };

        let post_state = self.process_slots(slot)?.process_block(&final_block)?;

        final_block.state_root = post_state.hash_tree_root();

        Ok((
            final_block,
            post_state,
            aggregated_attestations,
            aggregated_signatures,
        ))
    }

    /// Merge selected (AggregatedAttestation, Proof) entries that share the
    /// same AttestationData into a single recursive proof via
    /// `aggregate_with_children`, preserving first-occurrence order. A block
    /// body must contain at most one entry per AttestationData (spec invariant).
    fn compact_proofs_by_data(
        &self,
        entries: Vec<(AggregatedAttestation, AggregatedSignatureProof)>,
        log_inv_rate: usize,
    ) -> Result<Vec<(AggregatedAttestation, AggregatedSignatureProof)>> {
        if entries.len() <= 1 {
            return Ok(entries);
        }

        let mut order: Vec<H256> = Vec::new();
        let mut groups: HashMap<H256, Vec<(AggregatedAttestation, AggregatedSignatureProof)>> =
            HashMap::new();
        for (att, proof) in entries {
            let dr = att.data.hash_tree_root();
            if !groups.contains_key(&dr) {
                order.push(dr);
            }
            groups.entry(dr).or_default().push((att, proof));
        }

        let mut compacted: Vec<(AggregatedAttestation, AggregatedSignatureProof)> =
            Vec::with_capacity(order.len());

        for data_root in order {
            let group = groups.remove(&data_root).expect("group exists for data_root");
            if group.len() == 1 {
                compacted.extend(group);
                continue;
            }

            let data = group[0].0.data.clone();

            let child_pk_vecs: Vec<Vec<PublicKey>> = group
                .iter()
                .map(|(_, proof)| {
                    proof
                        .get_participant_indices()
                        .into_iter()
                        .filter_map(|vid| {
                            self.validators
                                .get(vid)
                                .ok()
                                .map(|v| v.attestation_pubkey.clone())
                        })
                        .collect()
                })
                .collect();

            let children_arg: Vec<(&[PublicKey], &AggregatedSignatureProof)> = child_pk_vecs
                .iter()
                .zip(group.iter())
                .map(|(pks, (_, proof))| (pks.as_slice(), proof))
                .collect();

            let mut all_validator_ids: Vec<u64> = group
                .iter()
                .flat_map(|(_, proof)| proof.get_participant_indices())
                .collect();
            all_validator_ids.sort();
            all_validator_ids.dedup();
            let all_participants = AggregationBits::from_validator_indices(&all_validator_ids);

            match AggregatedSignatureProof::aggregate_with_children(
                all_participants.clone(),
                &children_arg,
                Vec::<PublicKey>::new(),
                Vec::<Signature>::new(),
                data_root,
                data.slot.0 as u32,
                log_inv_rate,
            ) {
                Ok(merged_proof) => {
                    info!(
                        slot = data.slot.0,
                        children = group.len(),
                        validators = all_validator_ids.len(),
                        "compact_proofs_by_data: merged proofs into recursive proof"
                    );
                    compacted.push((
                        AggregatedAttestation {
                            aggregation_bits: all_participants,
                            data,
                        },
                        merged_proof,
                    ));
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "compact_proofs_by_data: merge failed, keeping proofs separate"
                    );
                    compacted.extend(group);
                }
            }
        }

        Ok(compacted)
    }
}

fn is_proposer_for(validator_index: u64, slot: Slot, num_validators: u64) -> bool {
    slot.0 % num_validators == validator_index
}
