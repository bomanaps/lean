// Lean validator client with XMSS signing support
use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::Deserialize;

use anyhow::{Context, Result, anyhow, bail};
use containers::{
    AggregatedSignatureProof, AggregationBits, AttestationData, AttestationSignatures, Block,
    BlockSignatures, SignedAggregatedAttestation, SignedAttestation, SignedBlock, Slot,
};
use fork_choice::store::Store;
use metrics::{METRICS, stop_and_discard, stop_and_record};
use ssz::H256;
use ssz::SszHash;
use tracing::{info, warn};
use try_from_iterator::TryFromIterator as _;

pub mod keys;

use keys::KeyManager;
use xmss::{PublicKey, Signature};

/// Entry in an annotated_validators.yaml file.
/// Each validator index has two entries: one for the attester key and one for the proposer key,
/// distinguished by the filename containing "attester" or "proposer".
/// Single-key format (e.g. validator_N_sk.ssz with neither keyword) is also accepted and
/// uses the same file for both attestation and proposal.
#[derive(Debug, Clone, Deserialize)]
pub struct AnnotatedValidatorEntry {
    pub index: u64,
    pub pubkey_hex: String,
    pub privkey_file: String,
}

pub type ValidatorRegistry = HashMap<String, Vec<AnnotatedValidatorEntry>>;

#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    pub node_id: String,
    pub validator_indices: Vec<u64>,
    /// Maps validator index → (attestation_privkey_filename, proposal_privkey_filename).
    /// Populated from annotated_validators.yaml; empty when constructed manually (tests).
    pub key_files: HashMap<u64, (String, String)>,
}

impl ValidatorConfig {
    pub fn load_from_file(path: impl AsRef<Path>, node_id: &str) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let registry: ValidatorRegistry = serde_yaml::from_reader(file)?;

        let entries = registry
            .get(node_id)
            .ok_or_else(|| anyhow!("Node `{node_id}` not found in validator registry"))?;

        // Group entries by validator index, mapping attester/proposer filenames by keyword.
        let mut file_map: HashMap<u64, (Option<String>, Option<String>)> = HashMap::new();
        for entry in entries {
            let slot = file_map.entry(entry.index).or_default();
            if entry.privkey_file.contains("attester") {
                slot.0 = Some(entry.privkey_file.clone());
            } else if entry.privkey_file.contains("proposer") {
                slot.1 = Some(entry.privkey_file.clone());
            } else {
                // Single-key format: same file for both keys.
                slot.0 = Some(entry.privkey_file.clone());
                slot.1 = Some(entry.privkey_file.clone());
            }
        }

        let mut key_files: HashMap<u64, (String, String)> = HashMap::new();
        for (idx, (att, prop)) in file_map {
            let att =
                att.ok_or_else(|| anyhow!("No attester privkey_file for validator {idx}"))?;
            let prop =
                prop.ok_or_else(|| anyhow!("No proposer privkey_file for validator {idx}"))?;
            key_files.insert(idx, (att, prop));
        }

        let mut validator_indices: Vec<u64> = key_files.keys().cloned().collect();
        validator_indices.sort_unstable();

        info!(node_id = %node_id, indices = ?validator_indices, "Validator config loaded...");

        Ok(ValidatorConfig {
            node_id: node_id.to_string(),
            validator_indices,
            key_files,
        })
    }

    pub fn is_assigned(&self, index: u64) -> bool {
        self.validator_indices.contains(&index)
    }
}

pub struct ValidatorService {
    pub config: ValidatorConfig,
    pub num_validators: u64,
    key_manager: Option<KeyManager>,
    /// Whether this node performs aggregation duties (devnet-3)
    is_aggregator: bool,
}

/// Greedily extend `children` with proofs from `candidates` that maximally cover
/// validators not yet in `covered`.
///
/// Mirrors the spec's `select_greedily`:
/// each iteration picks the candidate covering the most uncovered validators,
/// until no candidate adds new coverage. `covered` is updated in place so
/// callers can chain two passes (new payloads first, then known payloads).
fn extend_children_greedily<'a>(
    candidates: &'a [AggregatedSignatureProof],
    children: &mut Vec<&'a AggregatedSignatureProof>,
    covered: &mut HashSet<u64>,
) {
    // Track which candidates are still eligible (not yet selected).
    let mut remaining: Vec<&'a AggregatedSignatureProof> = candidates.iter().collect();

    loop {
        // Find the candidate that covers the most uncovered validators.
        let best = remaining
            .iter()
            .enumerate()
            .map(|(pos, proof)| {
                let new_cov = proof
                    .participants
                    .to_validator_indices()
                    .into_iter()
                    .filter(|vid| !covered.contains(vid))
                    .count();
                (pos, new_cov)
            })
            .max_by_key(|&(_, new_cov)| new_cov);

        let Some((pos, new_cov)) = best else { break };
        if new_cov == 0 {
            // No remaining candidate adds coverage — done.
            break;
        }

        let proof = remaining.remove(pos);
        for vid in proof.participants.to_validator_indices() {
            covered.insert(vid);
        }
        children.push(proof);
    }
}

impl ValidatorService {
    pub fn new(config: ValidatorConfig, num_validators: u64) -> Self {
        Self::new_with_aggregator(config, num_validators, false)
    }

    pub fn new_with_aggregator(
        config: ValidatorConfig,
        num_validators: u64,
        is_aggregator: bool,
    ) -> Self {
        info!(
            node_id = %config.node_id,
            indices = ?config.validator_indices,
            total_validators = num_validators,
            is_aggregator = is_aggregator,
            "VALIDATOR INITIALIZED SUCCESSFULLY"
        );

        METRICS.get().map(|metrics| {
            metrics
                .lean_validators_count
                .set(config.validator_indices.len() as i64)
        });

        Self {
            config,
            num_validators,
            key_manager: None,
            is_aggregator,
        }
    }

    pub fn new_with_keys(
        config: ValidatorConfig,
        num_validators: u64,
        keys_dir: impl AsRef<Path>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_keys_and_aggregator(config, num_validators, keys_dir, false)
    }

    pub fn new_with_keys_and_aggregator(
        config: ValidatorConfig,
        num_validators: u64,
        keys_dir: impl AsRef<Path>,
        is_aggregator: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut key_manager = KeyManager::new(&keys_dir)?;

        // Load keys for all assigned validators.
        // When annotated_validators.yaml was used, key_files carries explicit filenames;
        // otherwise fall back to the legacy convention-based paths.
        for &idx in &config.validator_indices {
            if let Some((attest_file, proposal_file)) = config.key_files.get(&idx) {
                let attest_path = keys_dir.as_ref().join(attest_file);
                let proposal_path = keys_dir.as_ref().join(proposal_file);
                key_manager.load_keys_from_files(idx, &attest_path, &proposal_path)?;
            } else {
                key_manager.load_keys(idx)?;
            }
        }

        info!(
            node_id = %config.node_id,
            indices = ?config.validator_indices,
            total_validators = num_validators,
            keys_loaded = config.validator_indices.len(),
            is_aggregator = is_aggregator,
            "VALIDATOR INITIALIZED WITH XMSS KEYS"
        );

        METRICS.get().map(|metrics| {
            metrics
                .lean_validators_count
                .set(config.validator_indices.len() as i64)
        });

        Ok(Self {
            config,
            num_validators,
            key_manager: Some(key_manager),
            is_aggregator,
        })
    }

    pub fn get_proposer_for_slot(&self, slot: Slot) -> Option<u64> {
        if self.num_validators == 0 {
            return None;
        }
        let proposer = slot.0 % self.num_validators;

        if self.config.is_assigned(proposer) {
            Some(proposer)
        } else {
            None
        }
    }

    /// Check if this node is an aggregator for the given slot (devnet-3)
    /// For devnet-3, aggregator selection is simplified: a node is an aggregator
    /// if it has validator duties and is_aggregator is enabled via config
    pub fn is_aggregator_for_slot(&self, _slot: Slot) -> bool {
        self.is_aggregator && !self.config.validator_indices.is_empty()
    }

    /// Perform aggregation duty if this node is an aggregator.
    ///
    /// Implements the spec's three-phase `aggregate()` function:
    ///   1. **Select** — greedily pick existing proofs (new payloads first, then known)
    ///      that maximise validator coverage (`select_greedily(new, known)`).
    ///   2. **Fill** — collect raw gossip sigs for validators not covered by children.
    ///   3. **Aggregate** — produce a single recursive XMSS proof.
    ///
    /// Returns `Some((attestations, consumed_data_roots))` where `consumed_data_roots`
    /// is the set of data_roots whose gossip signatures were incorporated into a proof.
    /// The caller must remove those keys from `store.gossip_signatures` to prevent
    /// re-aggregation in future rounds (spec: "consumed gossip signatures are removed").
    ///
    /// Returns `None` if this node has no aggregation duty or nothing to aggregate.
    pub fn maybe_aggregate(
        &self,
        store: &Store,
        slot: Slot,
        log_inv_rate: usize,
    ) -> Option<(Vec<SignedAggregatedAttestation>, HashSet<H256>)> {
        if !self.is_aggregator_for_slot(slot) {
            return None;
        }

        // Get the head state to access validator public keys.
        let head_state = store.states.get(&store.head)?;

        // Group fresh individual gossip signatures by data_root.
        let mut gossip_groups: HashMap<H256, Vec<(u64, Signature)>> = HashMap::new();
        for (sig_key, signature) in &store.gossip_signatures {
            gossip_groups
                .entry(sig_key.data_root)
                .or_default()
                .push((sig_key.validator_id, signature.clone()));
        }

        // Spec: iterate over new.keys() | gossip_sigs.keys().
        // Known payloads alone cannot trigger aggregation — they only help extend coverage.
        let mut all_data_roots: HashSet<H256> = gossip_groups.keys().copied().collect();
        for data_root in store.latest_new_aggregated_payloads.keys() {
            all_data_roots.insert(*data_root);
        }

        if all_data_roots.is_empty() {
            info!(slot = slot.0, "No signatures to aggregate");
            return None;
        }

        let mut aggregated_attestations: Vec<SignedAggregatedAttestation> = Vec::new();
        // data_roots whose raw gossip sigs were consumed into a proof; the caller will
        // remove these from the store to match spec cleanup semantics.
        let mut consumed_data_roots: HashSet<H256> = HashSet::new();

        for data_root in all_data_roots {
            let Some(attestation_data) = store.attestation_data_by_root.get(&data_root).cloned()
            else {
                warn!(
                    data_root = %format!("0x{:x}", data_root),
                    "Could not find attestation data for aggregation group"
                );
                continue;
            };

            // Only aggregate attestations for the current slot.
            if attestation_data.slot != slot {
                continue;
            }

            // ── Phase 1: Select ──────────────────────────────────────────────────────
            // Two-pass greedy child selection matching spec `select_greedily(new, known)`.
            // New payloads go first (uncommitted work); known payloads fill remaining gaps.
            let mut children: Vec<&AggregatedSignatureProof> = Vec::new();
            let mut covered_by_children: HashSet<u64> = HashSet::new();

            extend_children_greedily(
                store
                    .latest_new_aggregated_payloads
                    .get(&data_root)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]),
                &mut children,
                &mut covered_by_children,
            );
            extend_children_greedily(
                store
                    .latest_known_aggregated_payloads
                    .get(&data_root)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]),
                &mut children,
                &mut covered_by_children,
            );

            // ── Phase 2: Fill ────────────────────────────────────────────────────────
            // Collect raw gossip sigs for validators not already covered by children,
            // sorted ascending for deterministic bitfield construction.
            let mut entries: Vec<(u64, Signature)> = gossip_groups
                .get(&data_root)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|(vid, _)| {
                    !covered_by_children.contains(vid)
                        && head_state.validators.get(*vid).is_ok()
                })
                .collect();
            entries.sort_by_key(|(vid, _)| *vid);

            let mut fresh_validator_ids: Vec<u64> = Vec::new();
            let mut fresh_public_keys: Vec<PublicKey> = Vec::new();
            let mut fresh_signatures: Vec<Signature> = Vec::new();

            for (vid, sig) in entries {
                let validator = head_state.validators.get(vid).unwrap();
                fresh_validator_ids.push(vid);
                fresh_public_keys.push(validator.attestation_pubkey.clone());
                fresh_signatures.push(sig);
            }

            if children.is_empty() && fresh_validator_ids.is_empty() {
                continue;
            }

            // ── Spec guard ───────────────────────────────────────────────────────────
            // A lone child proof with no fresh raw signatures is already a valid proof —
            // skip re-aggregation. Matches spec rule:
            //   `if not raw_entries and len(child_proofs) < 2: continue`
            if fresh_validator_ids.is_empty() && children.len() < 2 {
                continue;
            }

            // ── Phase 3: Aggregate ───────────────────────────────────────────────────
            let timer = METRICS.get().map(|m| {
                m.lean_committee_signatures_aggregation_time_seconds
                    .start_timer()
            });

            let proof = if children.is_empty() {
                // No child proofs: simple fresh aggregation from raw sigs only.
                let participants = AggregationBits::from_validator_indices(&fresh_validator_ids);
                match AggregatedSignatureProof::aggregate(
                    participants,
                    fresh_public_keys,
                    fresh_signatures,
                    data_root,
                    attestation_data.slot.0 as u32,
                    log_inv_rate,
                ) {
                    Ok(p) => {
                        stop_and_record(timer);
                        p
                    }
                    Err(e) => {
                        stop_and_discard(timer);
                        warn!(error = %e, "Failed to create aggregated signature proof");
                        continue;
                    }
                }
            } else {
                // Have child proofs: recursive aggregation — children compress prior rounds,
                // fresh raw sigs fill any remaining uncovered validators.
                let child_pk_vecs: Vec<Vec<PublicKey>> = children
                    .iter()
                    .map(|child| {
                        child
                            .participants
                            .to_validator_indices()
                            .into_iter()
                            .filter_map(|vid| {
                                head_state
                                    .validators
                                    .get(vid)
                                    .ok()
                                    .map(|v| v.attestation_pubkey.clone())
                            })
                            .collect()
                    })
                    .collect();

                let children_arg: Vec<(&[PublicKey], &AggregatedSignatureProof)> = child_pk_vecs
                    .iter()
                    .zip(children.iter())
                    .map(|(pks, proof)| (pks.as_slice(), *proof))
                    .collect();

                let mut all_validator_ids: Vec<u64> =
                    covered_by_children.iter().copied().collect();
                all_validator_ids.extend_from_slice(&fresh_validator_ids);
                all_validator_ids.sort();
                all_validator_ids.dedup();
                let all_participants =
                    AggregationBits::from_validator_indices(&all_validator_ids);

                match AggregatedSignatureProof::aggregate_with_children(
                    all_participants,
                    &children_arg,
                    fresh_public_keys,
                    fresh_signatures,
                    data_root,
                    attestation_data.slot.0 as u32,
                    log_inv_rate,
                ) {
                    Ok(p) => {
                        stop_and_record(timer);
                        p
                    }
                    Err(e) => {
                        stop_and_discard(timer);
                        warn!(error = %e, "Failed to create recursive aggregated signature proof");
                        continue;
                    }
                }
            };

            info!(
                slot = slot.0,
                validators = fresh_validator_ids.len() + covered_by_children.len(),
                children = children.len(),
                data_root = %format!("0x{:x}", data_root),
                "Created aggregated attestation"
            );

            aggregated_attestations.push(SignedAggregatedAttestation {
                data: attestation_data,
                proof,
            });

            // Mark as consumed so the caller can evict the raw sigs from the store.
            consumed_data_roots.insert(data_root);
        }

        if aggregated_attestations.is_empty() {
            None
        } else {
            Some((aggregated_attestations, consumed_data_roots))
        }
    }

    /// Sign a block given pre-fetched attestation data.
    ///
    /// Unlike `sign_block`, this method does not need a `&Store` reference.
    /// The validator task calls `BuildAttestationData` on the chain task first,
    /// receives the `AttestationData` via oneshot, then calls this method.
    /// This keeps XMSS signing (~170ms) entirely off the chain task's thread.
    pub fn sign_block_with_data(
        &self,
        block: Block,
        validator_index: u64,
        attestation_signatures: Vec<AggregatedSignatureProof>,
    ) -> Result<SignedBlock> {
        let Some(key_manager) = self.key_manager.as_ref() else {
            bail!("unable to sign block - keymanager not configured");
        };

        let proposer_signature = {
            let sign_timer = METRICS.get().map(|metrics| {
                metrics
                    .lean_pq_sig_attestation_signing_time_seconds
                    .start_timer()
            });

            key_manager
                .sign_proposal(
                    validator_index,
                    block.slot.0 as u32,
                    block.hash_tree_root(),
                )
                .context("failed to sign block")
                .inspect_err(|_| stop_and_discard(sign_timer))?
        };

        let signature = BlockSignatures {
            attestation_signatures: AttestationSignatures::try_from_iter(attestation_signatures)
                .context("invalid attestation signatures")?,
            proposer_signature,
        };

        Ok(SignedBlock { block, signature })
    }

    /// Create and sign attestations for all validators given pre-fetched attestation data.
    ///
    /// Unlike `create_attestations`, this method does not need a `&Store` reference.
    /// The validator task calls `BuildAttestationData` on the chain task first,
    /// receives the `AttestationData` via oneshot, then calls this method.
    /// This keeps XMSS signing entirely off the chain task's thread.
    pub fn create_attestations_from_data(
        &self,
        slot: Slot,
        attestation_data: AttestationData,
    ) -> Vec<SignedAttestation> {
        if attestation_data.target.slot < attestation_data.source.slot {
            warn!(
                target_slot = attestation_data.target.slot.0,
                source_slot = attestation_data.source.slot.0,
                "Skipping attestation: target slot must be >= source slot"
            );
            return vec![];
        }

        self.config
            .validator_indices
            .iter()
            .filter_map(|&idx| {
                let signature = if let Some(ref key_manager) = self.key_manager {
                    let message = attestation_data.hash_tree_root();
                    let epoch = slot.0 as u32;

                    let _timer = METRICS.get().map(|metrics| {
                        metrics
                            .lean_pq_sig_attestation_signing_time_seconds
                            .start_timer()
                    });

                    match key_manager.sign_attestation(idx, epoch, message) {
                        Ok(sig) => {
                            METRICS.get().map(|metrics| {
                                metrics.lean_pq_sig_attestation_signatures_total.inc();
                            });
                            info!(
                                slot = slot.0,
                                validator = idx,
                                target_slot = attestation_data.target.slot.0,
                                source_slot = attestation_data.source.slot.0,
                                "Created signed attestation"
                            );
                            sig
                        }
                        Err(e) => {
                            warn!(
                                validator = idx,
                                error = %e,
                                "Failed to sign attestation, skipping"
                            );
                            return None;
                        }
                    }
                } else {
                    info!(
                        slot = slot.0,
                        validator = idx,
                        "Created attestation with zero signature"
                    );
                    Signature::default()
                };

                Some(SignedAttestation {
                    validator_id: idx,
                    message: attestation_data.clone(),
                    signature,
                })
            })
            .collect()
    }
}
