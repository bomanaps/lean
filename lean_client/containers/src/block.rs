use crate::{Slot, State};
use anyhow::{Context, Result, ensure};
use metrics::METRICS;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use ssz::{H256, Ssz, SszHash};
use xmss::Signature;

use crate::attestation::{AggregatedAttestations, AttestationSignatures};

/// The body of a block, containing payload data.
///
/// Attestations are stored WITHOUT signatures. Signatures are aggregated
/// separately in BlockSignatures to match the spec architecture.
// todo(containers): default implementation doesn't make sense here.
#[derive(Clone, Debug, Ssz, Serialize, Deserialize, Default)]
pub struct BlockBody {
    #[serde(with = "crate::serde_helpers::aggregated_attestations")]
    pub attestations: AggregatedAttestations,
}

#[derive(Clone, Debug, Ssz, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeader {
    pub slot: Slot,
    pub proposer_index: u64,
    pub parent_root: H256,
    pub state_root: H256,
    pub body_root: H256,
}

#[derive(Clone, Debug, Ssz, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    pub slot: Slot,
    pub proposer_index: u64,
    pub parent_root: H256,
    pub state_root: H256,
    pub body: BlockBody,
}

// todo(containers): default implementation doesn't make sense here
#[derive(Debug, Clone, Ssz, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BlockSignatures {
    #[serde(with = "crate::serde_helpers::attestation_signatures")]
    pub attestation_signatures: AttestationSignatures,
    pub proposer_signature: Signature,
}

/// Signed block for devnet4: block body + aggregated signatures.
/// Proposer attestation is no longer embedded in the block message.
#[derive(Clone, Debug, Ssz, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedBlock {
    /// The proposed block.
    pub block: Block,
    /// Aggregated signature payload (attestation proofs + proposer signature).
    #[serde(alias = "signatures")]
    pub signature: BlockSignatures,
}

impl SignedBlock {
    /// Verify all XMSS signatures in this signed block.
    ///
    /// Verifies each aggregated attestation proof against the participant
    /// validator public keys from parent state.
    ///
    /// Returns `Ok(())` if all signatures are valid, or an error describing the failure.
    pub fn verify_signatures(&self, parent_state: State) -> Result<()> {
        let block = &self.block;
        let signature = &self.signature;
        let aggregated_attestations = &block.body.attestations;
        let attestation_signatures = &signature.attestation_signatures;

        // Verify signature count matches aggregated attestation count
        ensure!(
            aggregated_attestations.len_u64() == attestation_signatures.len_u64(),
            "attestation signature count mismatch: {} attestations vs {} signatures",
            aggregated_attestations.len_u64(),
            attestation_signatures.len_u64()
        );

        let validators = &parent_state.validators;
        let num_validators = validators.len_u64();

        // Phase 1: collect all verification inputs (serial - reads from State)
        let verification_tasks = aggregated_attestations
            .into_iter()
            .zip(attestation_signatures.into_iter())
            .map(|(aggregated_attestation, aggregated_signature)| {
                let validator_ids = aggregated_attestation
                    .aggregation_bits
                    .to_validator_indices();

                // Ensure all validators exist in the active set
                for validator_id in &validator_ids {
                    ensure!(
                        *validator_id < num_validators,
                        "validator index {validator_id} out of range (max {num_validators})"
                    );
                }

                let attestation_data_root = aggregated_attestation.data.hash_tree_root();
                let slot = aggregated_attestation.data.slot.0 as u32;

                // Collect validators, returning error if any not found
                let public_keys = validator_ids
                    .into_iter()
                    .map(|id| {
                        validators
                            .get(id)
                            .map(|validator| validator.attestation_pubkey.clone())
                            .map_err(Into::into)
                    })
                    .collect::<Result<Vec<_>>>()?;

                Ok((
                    public_keys,
                    attestation_data_root,
                    slot,
                    aggregated_signature,
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        // Phase 2: verify all proofs in parallel (CPU-intensive XMSS verification)
        verification_tasks.into_par_iter().try_for_each(
            |(public_keys, attestation_data_root, slot, aggregated_signature)| {
                aggregated_signature
                    .verify(public_keys, attestation_data_root, slot)
                    .context("attestation aggregated signature verification failed")
            },
        )?;

        // Verify the proposer's XMSS signature over the block root
        let proposer_index = block.proposer_index;
        ensure!(
            proposer_index < num_validators,
            "proposer index {proposer_index} out of range (max {num_validators})"
        );

        let proposer = validators
            .get(proposer_index)
            .context(format!("proposer {proposer_index} not found in state"))?;

        let _timer = METRICS.get().map(|metrics| {
            metrics
                .lean_pq_sig_attestation_verification_time_seconds
                .start_timer()
        });

        signature
            .proposer_signature
            .verify(
                &proposer.proposal_pubkey,
                block.slot.0 as u32,
                block.hash_tree_root(),
            )
            .context("proposer signature verification failed")?;

        Ok(())
    }
}
