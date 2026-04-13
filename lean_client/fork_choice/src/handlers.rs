use anyhow::{Context, Result, anyhow, bail, ensure};
use containers::{
    AttestationData, SignatureKey, SignedAggregatedAttestation, SignedAttestation, SignedBlock,
};
use metrics::METRICS;
use ssz::{H256, SszHash};
use tracing::warn;

use crate::block_cache::BlockCache;
use crate::store::{
    INTERVALS_PER_SLOT, MILLIS_PER_INTERVAL, STATE_PRUNE_BUFFER, Store, tick_interval, update_head,
};

#[inline]
pub fn on_tick(store: &mut Store, time_millis: u64, has_proposal: bool) {
    // Calculate target time in intervals using milliseconds (800ms intervals)
    // genesis_time is in seconds, convert to milliseconds for calculation
    let genesis_millis = store.config.genesis_time * 1000;
    let elapsed_millis = time_millis.saturating_sub(genesis_millis);
    let tick_interval_time = elapsed_millis / MILLIS_PER_INTERVAL;

    // Tick forward one interval at a time
    while store.time < tick_interval_time {
        // Check if proposal should be signaled for next interval
        let should_signal_proposal = has_proposal && (store.time + 1) == tick_interval_time;

        // Advance by one interval with appropriate signaling
        tick_interval(store, should_signal_proposal);
    }
}

/// 1. The blocks voted for must exist in our store.
/// 2. A vote cannot span backwards in time (source > target).
/// 3. A vote cannot be for a future slot.
/// 4. Checkpoint slots must match block slots.
fn validate_attestation_data(store: &Store, data: &AttestationData) -> Result<()> {
    // Topology: history is linear and monotonic — source <= target <= head.
    ensure!(
        data.source.slot <= data.target.slot,
        "Source checkpoint slot {} must not exceed target slot {}",
        data.source.slot.0,
        data.target.slot.0
    );
    ensure!(
        data.head.slot >= data.target.slot,
        "Head slot {} must not be older than target slot {}",
        data.head.slot.0,
        data.target.slot.0
    );

    // Validate checkpoint slots match block slots.
    // Skip the source slot-match when the root is the store's known justified or
    // finalized checkpoint: after checkpoint sync the anchor block sits at
    // anchor_slot in store.blocks but the checkpoint carries the actual historical
    // slot from the downloaded state (e.g. 100994 vs anchor 101002).
    let source_block = &store.blocks[&data.source.root];
    let target_block = &store.blocks[&data.target.root];
    let head_block = &store.blocks[&data.head.root];

    let source_is_trusted_checkpoint = data.source.root == store.latest_justified.root
        || data.source.root == store.latest_finalized.root;

    if !source_is_trusted_checkpoint {
        ensure!(
            source_block.slot == data.source.slot,
            "Source checkpoint slot mismatch: checkpoint {} vs block {}",
            data.source.slot.0,
            source_block.slot.0
        );
    }

    ensure!(
        target_block.slot == data.target.slot,
        "Target checkpoint slot mismatch: checkpoint {} vs block {}",
        data.target.slot.0,
        target_block.slot.0
    );

    ensure!(
        head_block.slot == data.head.slot,
        "Head checkpoint slot mismatch: checkpoint {} vs block {}",
        data.head.slot.0,
        head_block.slot.0
    );

    // Validate attestation is not too far in the future
    // We allow a small margin for clock disparity (1 slot), but no further.
    let current_slot = store.time / INTERVALS_PER_SLOT;

    ensure!(
        data.slot.0 <= current_slot + 1,
        "Attestation too far in future: attestation slot {} > current slot {} + 1",
        data.slot.0,
        current_slot
    );

    Ok(())
}

/// Returns the first block root (source, target, or head) referenced by `attestation_data`
/// that is not yet present in the store, or `None` if all are known.
fn find_unknown_attestation_block(
    store: &Store,
    attestation_data: &AttestationData,
) -> Option<H256> {
    [
        attestation_data.source.root,
        attestation_data.target.root,
        attestation_data.head.root,
    ]
    .into_iter()
    .find(|root| !store.blocks.contains_key(root))
}

/// Process a signed attestation received via gossip network
///
/// 1. Validates the attestation data
/// 2. Stores the signature in the gossip signature map
/// 3. Processes the attestation data via on_attestation
///
#[inline]
pub fn on_gossip_attestation(
    store: &mut Store,
    signed_attestation: SignedAttestation,
) -> Result<()> {
    let _timer = METRICS.get().map(|metrics| {
        metrics
            .lean_attestation_validation_time_seconds
            .start_timer()
    });

    let validator_id = signed_attestation.validator_id;
    let attestation_data = signed_attestation.message.clone();

    // Queue attestation if any referenced block is not yet in the store.
    // When the missing block arrives, pending attestations are retried.
    if let Some(missing_root) = find_unknown_attestation_block(store, &attestation_data) {
        store
            .pending_attestations
            .entry(missing_root)
            .or_default()
            .push(signed_attestation);
        store.pending_fetch_roots.insert(missing_root);
        METRICS.get().map(|m| {
            m.grandine_pending_fetch_roots
                .set(store.pending_fetch_roots.len() as i64)
        });
        return Ok(());
    }

    // Validate the attestation data first
    validate_attestation_data(store, &attestation_data).inspect_err(|_| {
        METRICS.get().map(|metrics| {
            metrics
                .lean_attestations_invalid_total
                .with_label_values(&["gossip"])
                .inc()
        });
    })?;

    // Non-aggregators validate attestation data but do not store or verify individual
    // signatures. Per leanSpec: only aggregators import gossip attestations for aggregation.
    // Subnet filtering is already enforced at the p2p subscription layer.
    if !store.is_aggregator {
        return Ok(());
    }

    let data_root = attestation_data.hash_tree_root();
    let sig_key = SignatureKey::new(signed_attestation.validator_id, data_root);

    // Skip expensive XMSS verification for already-known signatures.
    // Duplicate attestations arrive when the IDontWant buffer fills under CPU load,
    // causing peers to rebroadcast. Each verify costs ~100ms; the early exit breaks
    // the saturation loop without dropping vote data.
    if !store.gossip_signatures.contains_key(&sig_key) {
        // Verify individual XMSS signature against the validator's public key.
        // State is available: the pending-block check above confirmed target.root is in
        // the store, and states are stored 1:1 with blocks in process_block_internal.
        let key_state = store
            .states
            .get(&attestation_data.target.root)
            .ok_or_else(|| anyhow!("no state for target block {}", attestation_data.target.root))?;

        ensure!(
            validator_id < key_state.validators.len_u64(),
            "validator {} out of range (max {})",
            validator_id,
            key_state.validators.len_u64()
        );

        let pubkey = key_state
            .validators
            .get(validator_id)
            .map(|v| v.attestation_pubkey.clone())
            .map_err(|e| anyhow!("{e}"))?;

        signed_attestation
            .signature
            .verify(&pubkey, attestation_data.slot.0 as u32, data_root)
            .context("individual attestation signature verification failed")?;

        store
            .gossip_signatures
            .insert(sig_key, signed_attestation.signature);

        // Update gossip signatures gauge
        METRICS.get().map(|metrics| {
            metrics
                .lean_gossip_signatures
                .set(store.gossip_signatures.len() as i64);
        });
    } else {
        METRICS
            .get()
            .map(|m| m.grandine_xmss_verify_skipped_total.inc());
    }

    store
        .attestation_data_by_root
        .insert(data_root, attestation_data.clone());
    METRICS.get().map(|m| {
        m.grandine_attestation_data_by_root
            .set(store.attestation_data_by_root.len() as i64)
    });

    // Process the attestation data (not from block)
    on_attestation_internal(store, validator_id, attestation_data, false)
        .inspect_err(|_| {
            METRICS.get().map(|metrics| {
                metrics
                    .lean_attestations_invalid_total
                    .with_label_values(&["gossip"])
                    .inc()
            });
        })
        .inspect(|_| {
            METRICS.get().map(|metrics| {
                metrics
                    .lean_attestations_valid_total
                    .with_label_values(&["gossip"])
                    .inc()
            });
        })
}

/// Process an attestation and place it into the correct attestation stage
///
/// Attestation processing logic that updates the attestation
/// maps used for fork choice. We store AttestationData only (not signatures).
///
/// Attestations can come from:
/// - a block body (on-chain, `is_from_block=True`), or
/// - the gossip network (off-chain, `is_from_block=False`).
#[inline]
pub fn on_attestation(
    store: &mut Store,
    signed_attestation: SignedAttestation,
    is_from_block: bool,
) -> Result<()> {
    let _timer = METRICS.get().map(|metrics| {
        metrics
            .lean_attestation_validation_time_seconds
            .start_timer()
    });

    let validator_id = signed_attestation.validator_id;
    let attestation_data = signed_attestation.message.clone();

    // All three referenced roots (source, target, head) must be in the store.
    // For gossip: queue as pending if a block is missing, to be retried on arrival.
    // For block-body: a missing root means the block itself is invalid — reject it.
    if let Some(missing_root) = find_unknown_attestation_block(store, &attestation_data) {
        if is_from_block {
            bail!("block-body attestation references unknown block root {missing_root}");
        }
        store
            .pending_attestations
            .entry(missing_root)
            .or_default()
            .push(signed_attestation);
        store.pending_fetch_roots.insert(missing_root);
        METRICS.get().map(|m| {
            m.grandine_pending_fetch_roots
                .set(store.pending_fetch_roots.len() as i64)
        });
        return Ok(());
    }

    // Validate attestation data
    validate_attestation_data(store, &attestation_data).inspect_err(|_| {
        METRICS.get().map(|metrics| {
            metrics
                .lean_attestations_invalid_total
                .with_label_values(&[if is_from_block { "block" } else { "gossip" }])
                .inc()
        });
    })?;

    // Store attestation data indexed by hash for aggregation lookup
    let data_root = attestation_data.hash_tree_root();
    store
        .attestation_data_by_root
        .insert(data_root, attestation_data.clone());

    if !is_from_block && store.is_aggregator {
        // Store signature for later aggregation during block building.
        // Per leanSpec: only aggregators store gossip signatures, including own attestations.
        // Non-aggregator validators produce and gossip attestations but do not store the sig.
        let sig_key = SignatureKey::new(signed_attestation.validator_id, data_root);
        store
            .gossip_signatures
            .insert(sig_key, signed_attestation.signature);
        METRICS.get().map(|metrics| {
            metrics
                .lean_gossip_signatures
                .set(store.gossip_signatures.len() as i64)
        });
    }

    on_attestation_internal(store, validator_id, attestation_data, is_from_block)
        .inspect_err(|_| {
            METRICS.get().map(|metrics| {
                metrics
                    .lean_attestations_invalid_total
                    .with_label_values(&[if is_from_block { "block" } else { "gossip" }])
                    .inc()
            });
        })
        .inspect(|_| {
            METRICS.get().map(|metrics| {
                metrics
                    .lean_attestations_valid_total
                    .with_label_values(&[if is_from_block { "block" } else { "gossip" }])
                    .inc()
            });
        })
}

/// Process an aggregated attestation from the aggregation topic.
///
/// Verifies the aggregated XMSS proof against participant public keys and stores
/// it in `latest_new_aggregated_payloads`. At interval 3, these are merged with
/// `latest_known_aggregated_payloads` (from blocks) to compute safe target.
#[inline]
pub fn on_aggregated_attestation(
    store: &mut Store,
    signed_aggregated_attestation: SignedAggregatedAttestation,
) -> Result<()> {
    // Structure: { data: AttestationData, proof: AggregatedSignatureProof }
    let attestation_data = signed_aggregated_attestation.data.clone();
    let proof = signed_aggregated_attestation.proof.clone();

    // Queue if any referenced block is not yet in the store.
    if let Some(missing_root) = find_unknown_attestation_block(store, &attestation_data) {
        store
            .pending_aggregated_attestations
            .entry(missing_root)
            .or_default()
            .push(signed_aggregated_attestation);
        store.pending_fetch_roots.insert(missing_root);
        METRICS.get().map(|m| {
            m.grandine_pending_fetch_roots
                .set(store.pending_fetch_roots.len() as i64)
        });
        return Ok(());
    }

    // Validate attestation data (slot bounds, target validity, etc.)
    validate_attestation_data(store, &attestation_data)?;

    let data_root = attestation_data.hash_tree_root();
    store
        .attestation_data_by_root
        .insert(data_root, attestation_data.clone());
    METRICS.get().map(|m| {
        m.grandine_attestation_data_by_root
            .set(store.attestation_data_by_root.len() as i64)
    });

    // Verify aggregated XMSS proof against participant public keys.
    // State is available: the pending-block check above confirmed target.root is in the store,
    // and states are stored 1:1 with blocks in process_block_internal.
    let key_state = store
        .states
        .get(&attestation_data.target.root)
        .ok_or_else(|| anyhow!("no state for target block {}", attestation_data.target.root))?;

    // Guard before calling to_validator_indices() which panics on an empty bitfield.
    ensure!(
        proof.participants.0.iter().any(|b| *b),
        "aggregated attestation has empty participants bitfield"
    );

    let validator_ids = proof.participants.to_validator_indices();

    let public_keys = validator_ids
        .iter()
        .map(|&id| {
            key_state
                .validators
                .get(id)
                .map(|v| v.attestation_pubkey.clone())
                .map_err(Into::into)
        })
        .collect::<Result<Vec<_>>>()?;

    proof
        .verify(public_keys, data_root, attestation_data.slot.0 as u32)
        .context("aggregated attestation proof verification failed")?;

    // Store the verified proof in latest_new_aggregated_payloads, keyed by data_root
    store
        .latest_new_aggregated_payloads
        .entry(data_root)
        .or_default()
        .push(proof);

    METRICS.get().map(|metrics| {
        metrics
            .lean_attestations_valid_total
            .with_label_values(&["aggregation"])
            .inc();
        // Update gauge for new aggregated payloads count
        metrics
            .lean_latest_new_aggregated_payloads
            .set(store.latest_new_aggregated_payloads.len() as i64);
    });

    Ok(())
}

/// Internal attestation processing - stores AttestationData
fn on_attestation_internal(
    store: &mut Store,
    validator_id: u64,
    attestation_data: AttestationData,
    is_from_block: bool,
) -> Result<()> {
    let attestation_slot = attestation_data.slot;

    if is_from_block {
        // On-chain attestation processing
        if store
            .latest_known_attestations
            .get(&validator_id)
            .map_or(true, |existing| existing.slot < attestation_slot)
        {
            store
                .latest_known_attestations
                .insert(validator_id, attestation_data);
        }

        // Remove from new attestations if superseded
        if let Some(existing_new) = store.latest_new_attestations.get(&validator_id) {
            if existing_new.slot <= attestation_slot {
                store.latest_new_attestations.remove(&validator_id);
            }
        }
    } else {
        // Network gossip attestation processing - goes to "new" stage
        if store
            .latest_new_attestations
            .get(&validator_id)
            .map_or(true, |existing| existing.slot < attestation_slot)
        {
            store
                .latest_new_attestations
                .insert(validator_id, attestation_data);
        }
    }
    METRICS.get().map(|m| {
        m.grandine_fork_choice_known_attestations
            .set(store.latest_known_attestations.len() as i64);
        m.grandine_fork_choice_new_attestations
            .set(store.latest_new_attestations.len() as i64);
    });
    Ok(())
}

/// Process a new block and update the forkchoice state
///
/// 1. Validating the block's parent exists
/// 2. Computing the post-state via the state transition function
/// 3. Processing attestations included in the block body (on-chain)
/// 4. Updating the forkchoice head
/// 5. Processing the proposer's attestation (as if gossiped)
pub fn on_block(
    store: &mut Store,
    cache: &mut BlockCache,
    signed_block: SignedBlock,
) -> Result<()> {
    let block_root = signed_block.block.hash_tree_root();

    if store.blocks.contains_key(&block_root) {
        return Ok(());
    }

    let parent_root = signed_block.block.parent_root;

    if !store.states.contains_key(&parent_root) && !parent_root.is_zero() {
        bail!(
            "Err: (Fork-choice::Handlers::OnBlock) parent state not available for {:?}",
            &parent_root.as_bytes()[..4]
        );
    }

    process_block_internal(store, signed_block, block_root)?;
    process_pending_blocks(store, cache, vec![block_root]);

    Ok(())
}

fn process_block_internal(
    store: &mut Store,
    signed_block: SignedBlock,
    block_root: H256,
) -> Result<()> {
    let _timer = METRICS.get().map(|metrics| {
        metrics
            .lean_fork_choice_block_processing_time_seconds
            .start_timer()
    });

    let block = signed_block.block.clone();
    let attestations_count = block.body.attestations.len_u64();

    // Get parent state for validation
    let state = store
        .states
        .get(&block.parent_root)
        .ok_or(anyhow!("no parent state"))?;

    // Debug: Log parent state checkpoints before transition
    tracing::debug!(
        block_slot = block.slot.0,
        attestations_in_block = attestations_count,
        parent_justified_slot = state.latest_justified.slot.0,
        parent_finalized_slot = state.latest_finalized.slot.0,
        justified_slots_len = state.justified_slots.0.len(),
        "Processing block - parent state info"
    );

    // Verify block signatures against parent state before executing the state transition.
    // If any signature is invalid the error propagates and the block is rejected;
    // it never enters store.blocks or store.states.
    signed_block.verify_signatures(state.clone())?;

    // Execute state transition to get post-state (signatures verified above)
    let new_state = state.state_transition(signed_block.clone(), true)?;

    // Debug: Log new state checkpoints after transition
    tracing::debug!(
        block_slot = block.slot.0,
        new_justified_slot = new_state.latest_justified.slot.0,
        new_finalized_slot = new_state.latest_finalized.slot.0,
        new_justified_slots_len = new_state.justified_slots.0.len(),
        "Block processed - new state info"
    );

    store.blocks.insert(block_root, block.clone());
    store.states.insert(block_root, new_state.clone());

    // Retry attestations that arrived before this block was known.
    // Drain the queue for this root and re-process each attestation.
    // Attestations that still reference other unknown blocks are re-queued automatically.
    let pending = store
        .pending_attestations
        .remove(&block_root)
        .unwrap_or_default();
    for signed_att in pending {
        if let Err(err) = on_gossip_attestation(store, signed_att) {
            warn!(%err, "Pending attestation retry failed after block arrival");
        }
    }

    let pending_agg = store
        .pending_aggregated_attestations
        .remove(&block_root)
        .unwrap_or_default();
    for signed_agg in pending_agg {
        if let Err(err) = on_aggregated_attestation(store, signed_agg) {
            warn!(%err, "Pending aggregated attestation retry failed after block arrival");
        }
    }

    let justified_updated = new_state.latest_justified.slot > store.latest_justified.slot;
    let finalized_updated = new_state.latest_finalized.slot > store.latest_finalized.slot;

    if justified_updated {
        tracing::info!(
            old_justified = store.latest_justified.slot.0,
            new_justified = new_state.latest_justified.slot.0,
            "Store justified checkpoint updated!"
        );
        store.latest_justified = new_state.latest_justified.clone();
        store.justified_ever_updated = true;
        METRICS.get().map(|metrics| {
            let Some(slot) = new_state.latest_justified.slot.0.try_into().ok() else {
                warn!("unable to set latest_justified slot in metrics");
                return;
            };
            metrics.lean_latest_justified_slot.set(slot);
        });
    }
    if finalized_updated {
        tracing::info!(
            old_finalized = store.latest_finalized.slot.0,
            new_finalized = new_state.latest_finalized.slot.0,
            "Store finalized checkpoint updated!"
        );
        store.latest_finalized = new_state.latest_finalized.clone();
        store.finalized_ever_updated = true;
        METRICS.get().map(|metrics| {
            let Some(slot) = new_state.latest_finalized.slot.0.try_into().ok() else {
                warn!("unable to set latest_finalized slot in metrics");
                return;
            };
            metrics.lean_latest_finalized_slot.set(slot);
        });

        let keep_from = store
            .latest_finalized
            .slot
            .0
            .saturating_sub(STATE_PRUNE_BUFFER);
        store.states.retain(|_, state| state.slot.0 >= keep_from);
        store.blocks.retain(|_, block| block.slot.0 >= keep_from);

        // Prune stale attestation data whenever finalization advances.
        // Criterion: target.slot <= finalized_slot → stale, no longer affects fork choice.
        // attestation_data_by_root is the secondary index used for target.slot lookup and
        // must be pruned last so the retain calls above can still resolve target.slot.
        let finalized_slot = store.latest_finalized.slot.0;
        let adr = &store.attestation_data_by_root;
        store.gossip_signatures.retain(|key, _| {
            adr.get(&key.data_root)
                .map_or(true, |data| data.target.slot.0 > finalized_slot)
        });
        store.latest_known_aggregated_payloads.retain(|data_root, _| {
            adr.get(data_root)
                .map_or(true, |data| data.target.slot.0 > finalized_slot)
        });
        store.latest_new_aggregated_payloads.retain(|data_root, _| {
            adr.get(data_root)
                .map_or(true, |data| data.target.slot.0 > finalized_slot)
        });
        store
            .attestation_data_by_root
            .retain(|_, data| data.target.slot.0 > finalized_slot);
        METRICS.get().map(|m| {
            m.grandine_attestation_data_by_root
                .set(store.attestation_data_by_root.len() as i64)
        });
    }

    if !justified_updated && !finalized_updated {
        tracing::debug!(
            block_slot = block.slot.0,
            store_justified = store.latest_justified.slot.0,
            store_finalized = store.latest_finalized.slot.0,
            state_justified = new_state.latest_justified.slot.0,
            state_finalized = new_state.latest_finalized.slot.0,
            "No checkpoint updates from this block"
        );
    }

    // Process block body attestations as on-chain (is_from_block=true)
    let signatures = &signed_block.signature;
    let aggregated_attestations = &block.body.attestations;

    // Store aggregated proofs indexed by (validator_id, data_root) for future block building
    for (att_idx, aggregated_attestation) in aggregated_attestations.into_iter().enumerate() {
        let data_root = aggregated_attestation.data.hash_tree_root();

        // Store attestation data for safe target extraction
        // This is critical: without this, block attestations are invisible to update_safe_target()
        store
            .attestation_data_by_root
            .insert(data_root, aggregated_attestation.data.clone());

        // Get the corresponding proof from attestation_signatures and store it keyed by data_root
        if let Ok(proof_data) = signatures.attestation_signatures.get(att_idx as u64) {
            store
                .latest_known_aggregated_payloads
                .entry(data_root)
                .or_default()
                .push(proof_data.clone());
        }
    }

    // Update gauge for known aggregated payloads count
    METRICS.get().map(|metrics| {
        metrics
            .lean_latest_known_aggregated_payloads
            .set(store.latest_known_aggregated_payloads.len() as i64);
    });
    METRICS.get().map(|m| {
        m.grandine_attestation_data_by_root
            .set(store.attestation_data_by_root.len() as i64)
    });

    // Process each aggregated attestation's validators for fork choice.
    // Signatures have already been verified above via verify_signatures().
    // Per Devnet-2, we process attestation data directly (not SignedAttestation).
    for aggregated_attestation in aggregated_attestations.into_iter() {
        let validator_ids: Vec<u64> = aggregated_attestation
            .aggregation_bits
            .0
            .iter()
            .enumerate()
            .filter(|(_, bit)| **bit)
            .map(|(index, _)| index as u64)
            .collect();

        // Each validator in the aggregation votes for this attestation data
        for validator_id in validator_ids {
            on_attestation_internal(
                store,
                validator_id,
                aggregated_attestation.data.clone(),
                true, // is_from_block
            )?;
        }
    }

    update_head(store);

    Ok(())
}

pub fn process_pending_blocks(store: &mut Store, cache: &mut BlockCache, mut roots: Vec<H256>) {
    while let Some(parent_root) = roots.pop() {
        let children: Vec<(H256, SignedBlock)> = cache
            .get_children(&parent_root)
            .into_iter()
            .map(|p| (p.root, p.block.clone()))
            .collect();

        for (child_root, child_block) in children {
            cache.remove(&child_root);
            if process_block_internal(store, child_block, child_root).is_ok() {
                roots.push(child_root);
            }
        }
    }
}
