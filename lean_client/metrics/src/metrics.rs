use std::{sync::Arc, time::SystemTime};

use anyhow::{Context, Result};
use once_cell::sync::OnceCell;
use prometheus::{
    GaugeVec, Histogram, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, histogram_opts, opts,
};

pub static METRICS: OnceCell<Arc<Metrics>> = OnceCell::new();

#[derive(Debug)]
pub struct Metrics {
    /// Node information: name and version
    lean_node_info: GaugeVec,

    /// Start timestamp
    lean_node_start_time_seconds: IntGauge,

    // PQ Signature metrics
    /// Total number of individual attestation signatures
    pub lean_pq_sig_attestation_signatures_total: IntCounter,

    /// Total number of valid individual attestation signatures
    pub lean_pq_sig_attestation_signatures_valid_total: IntCounter,

    /// Total number of invalid individual attestation signatures
    pub lean_pq_sig_attestation_signatures_invalid_total: IntCounter,

    /// Time taken to sign an attestation
    pub lean_pq_sig_attestation_signing_time_seconds: Histogram,

    /// Time taken to verify an attestation signature
    pub lean_pq_sig_attestation_verification_time_seconds: Histogram,

    /// Total number of aggregated signatures
    pub lean_pq_sig_aggregated_signatures_total: IntCounter,

    /// Total number of attestations included into aggregated signatures
    pub lean_pq_sig_attestations_in_aggregated_signatures_total: IntCounter,

    /// Time taken to build an aggregated attestation signature
    pub lean_pq_sig_aggregated_signatures_building_time_seconds: Histogram,

    /// Time taken to verify an aggregated attestation signature
    pub lean_pq_sig_aggregated_signatures_verification_time_seconds: Histogram,

    /// Total number of valid aggregated signatures
    pub lean_pq_sig_aggregated_signatures_valid_total: IntCounter,

    /// Total number of invalid aggregated signatures
    pub lean_pq_sig_aggregated_signatures_invalid_total: IntCounter,

    // Fork-Choice Metrics
    /// Latest slot of the lean chain
    pub lean_head_slot: IntGauge,

    /// Current slot of the lean chain
    pub lean_current_slot: IntGauge,

    /// Safe target slot
    pub lean_safe_target_slot: IntGauge,

    /// Time taken to process block
    pub lean_fork_choice_block_processing_time_seconds: Histogram,

    /// Total number of valid attestations
    pub lean_attestations_valid_total: IntCounterVec,

    /// Total number of invalid attestations
    pub lean_attestations_invalid_total: IntCounterVec,

    /// Time taken to validate attestation
    pub lean_attestation_validation_time_seconds: Histogram,

    /// Total number of fork choice reorgs
    pub lean_fork_choice_reorgs_total: IntCounter,

    /// Depth of fork choice reorgs (in blocks)
    pub lean_fork_choice_reorg_depth: Histogram,

    // State Transition Metrics
    /// Latest justified slot
    pub lean_latest_justified_slot: IntGauge,

    /// Latest finalized slot
    pub lean_latest_finalized_slot: IntGauge,

    /// Total number of finalization attempts
    pub lean_finalizations_total: IntCounterVec,

    /// Time to process state transition
    pub lean_state_transition_time_seconds: Histogram,

    /// Total number of processed slots
    pub lean_state_transition_slots_processed_total: IntCounter,

    /// Time taken to process slots
    pub lean_state_transition_slots_processing_time_seconds: Histogram,

    /// Time taken to process block
    pub lean_state_transition_block_processing_time_seconds: Histogram,

    /// Total number of processed attestations
    pub lean_state_transition_attestations_processed_total: IntCounter,

    /// Time taken to process attestations
    pub lean_state_transition_attestations_processing_time_seconds: Histogram,

    // Validator metrics
    /// Number of validators managed by a node
    pub lean_validators_count: IntGauge,

    // Network Metrics
    /// Number of connected peers
    pub lean_connected_peers: IntGaugeVec,

    /// Total number of peer connection events
    lean_peer_connection_events_total: IntCounterVec,

    /// Total number of peer disconnection events
    lean_peer_disconnection_events_total: IntCounterVec,

    /// Number of gossip signatures in fork-choice store
    pub lean_gossip_signatures: IntGauge,

    /// Number of new aggregated payload items
    pub lean_latest_new_aggregated_payloads: IntGauge,

    /// Number of known aggregated payload items
    pub lean_latest_known_aggregated_payloads: IntGauge,

    /// Time taken to aggregate committee signatures
    pub lean_committee_signatures_aggregation_time_seconds: Histogram,

    /// Validator's is_aggregator status (1=true, 0=false)
    pub lean_is_aggregator: IntGauge,

    /// Node's attestation committee subnet
    pub lean_attestation_committee_subnet: IntGauge,

    /// Number of attestation committees (ATTESTATION_COMMITTEE_COUNT)
    pub lean_attestation_committee_count: IntGauge,

    // OOM Detection Metrics

    /// Number of entries in the attestation_data_by_root secondary index
    pub lean_attestation_data_by_root: IntGauge,

    /// Number of block roots queued for BlocksByRoot fetch (missing-block backlog)
    pub lean_pending_fetch_roots: IntGauge,

    /// Number of orphan blocks held in the backfill BlockCache (hard-capped at 1024)
    pub lean_block_cache_size: IntGauge,

    /// Gap between the network's current slot and the node's head slot (backfill depth)
    pub lean_slots_behind: IntGauge,

    /// Validators with finalized (known) attestations currently in the fork-choice store
    pub lean_fork_choice_known_attestations: IntGauge,

    /// Validators with pending (new/gossip) attestations in the fork-choice store
    pub lean_fork_choice_new_attestations: IntGauge,

    /// XMSS verifications skipped because the signature was already cached
    pub lean_xmss_verify_skipped_total: IntCounter,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        Ok(Self {
            lean_node_info: GaugeVec::new(
                opts!("lean_node_info", "Node information"),
                &["name", "version"],
            )?,
            lean_node_start_time_seconds: IntGauge::new(
                "lean_node_start_time_seconds",
                "Start timestamp",
            )?,

            // PQ Signature metrics
            lean_pq_sig_attestation_signatures_total: IntCounter::new(
                "lean_pq_sig_attestation_signatures_total",
                "Total number of individual attestation signatures",
            )?,
            lean_pq_sig_attestation_signatures_valid_total: IntCounter::new(
                "lean_pq_sig_attestation_signatures_valid_total",
                "Total number of valid individual attestation signatures",
            )?,
            lean_pq_sig_attestation_signatures_invalid_total: IntCounter::new(
                "lean_pq_sig_attestation_signatures_invalid_total",
                "Total number of invalid individual attestation signatures",
            )?,
            lean_pq_sig_attestation_signing_time_seconds: Histogram::with_opts(histogram_opts!(
                "lean_pq_sig_attestation_signing_time_seconds",
                "Time taken to sign an attestation",
                vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0],
            ))?,
            lean_pq_sig_attestation_verification_time_seconds: Histogram::with_opts(
                histogram_opts!(
                    "lean_pq_sig_attestation_verification_time_seconds",
                    "Time taken to verify an attestation signature",
                    vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0],
                ),
            )?,
            lean_pq_sig_aggregated_signatures_total: IntCounter::new(
                "lean_pq_sig_aggregated_signatures_total",
                "Total number of aggregated signatures",
            )?,
            lean_pq_sig_attestations_in_aggregated_signatures_total: IntCounter::new(
                "lean_pq_sig_attestations_in_aggregated_signatures_total",
                "Total number of attestations included into aggregated signatures",
            )?,
            lean_pq_sig_aggregated_signatures_building_time_seconds: Histogram::with_opts(
                histogram_opts!(
                    "lean_pq_sig_aggregated_signatures_building_time_seconds",
                    "Time taken to build an aggregated attestation signature",
                    vec![0.1, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 4.0]
                ),
            )?,
            lean_pq_sig_aggregated_signatures_verification_time_seconds: Histogram::with_opts(
                histogram_opts!(
                    "lean_pq_sig_aggregated_signatures_verification_time_seconds",
                    "Time taken to verify an aggregated attestation signature",
                    vec![0.1, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 4.0]
                ),
            )?,
            lean_pq_sig_aggregated_signatures_valid_total: IntCounter::new(
                "lean_pq_sig_aggregated_signatures_valid_total",
                "Total number of valid aggregated signatures",
            )?,
            lean_pq_sig_aggregated_signatures_invalid_total: IntCounter::new(
                "lean_pq_sig_aggregated_signatures_invalid_total",
                "Total number of invalid aggregated signatures",
            )?,

            // Fork-Choice Metrics
            lean_head_slot: IntGauge::new("lean_head_slot", "Latest slot of the lean chain")?,
            lean_current_slot: IntGauge::new(
                "lean_current_slot",
                "Current slot of the lean chain",
            )?,
            lean_safe_target_slot: IntGauge::new("lean_safe_target_slot", "Safe target slot")?,
            lean_fork_choice_block_processing_time_seconds: Histogram::with_opts(histogram_opts!(
                "lean_fork_choice_block_processing_time_seconds",
                "Time taken to process block",
                vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0, 1.25, 1.5, 2.0, 4.0]
            ))?,
            lean_attestations_valid_total: IntCounterVec::new(
                opts!(
                    "lean_attestations_valid_total",
                    "Total number of valid attestations",
                ),
                &["source"],
            )?,
            lean_attestations_invalid_total: IntCounterVec::new(
                opts!(
                    "lean_attestations_invalid_total",
                    "Total number of invalid attestations",
                ),
                &["source"],
            )?,
            lean_attestation_validation_time_seconds: Histogram::with_opts(histogram_opts!(
                "lean_attestation_validation_time_seconds",
                "Time taken to validate attestation",
                vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
            ))?,
            lean_fork_choice_reorgs_total: IntCounter::new(
                "lean_fork_choice_reorgs_total",
                "Total number of fork choice reorgs",
            )?,
            lean_fork_choice_reorg_depth: Histogram::with_opts(histogram_opts!(
                "lean_fork_choice_reorg_depth",
                "Depth of fork choice reorgs (in blocks)",
                vec![1.0, 2.0, 3.0, 5.0, 7.0, 10.0, 20.0, 30.0, 50.0, 100.0]
            ))?,

            // State Transition Metrics
            lean_latest_justified_slot: IntGauge::new(
                "lean_latest_justified_slot",
                "Latest justified slot",
            )?,
            lean_latest_finalized_slot: IntGauge::new(
                "lean_latest_finalized_slot",
                "Latest finalized slot",
            )?,
            lean_finalizations_total: IntCounterVec::new(
                opts!(
                    "lean_finalizations_total",
                    "Total number of finalization attempts",
                ),
                &["result"],
            )?,
            lean_state_transition_time_seconds: Histogram::with_opts(histogram_opts!(
                "lean_state_transition_time_seconds",
                "Time to process state transition",
                vec![0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 2.5, 3.0, 4.0]
            ))?,
            lean_state_transition_slots_processed_total: IntCounter::new(
                "lean_state_transition_slots_processed_total",
                "Total number of processed slots",
            )?,
            lean_state_transition_slots_processing_time_seconds: Histogram::with_opts(
                histogram_opts!(
                    "lean_state_transition_slots_processing_time_seconds",
                    "Time taken to process slots",
                    vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
                ),
            )?,
            lean_state_transition_block_processing_time_seconds: Histogram::with_opts(
                histogram_opts!(
                    "lean_state_transition_block_processing_time_seconds",
                    "Time taken to process block",
                    vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
                ),
            )?,
            lean_state_transition_attestations_processed_total: IntCounter::new(
                "lean_state_transition_attestations_processed_total",
                "Total number of processed attestations",
            )?,
            lean_state_transition_attestations_processing_time_seconds: Histogram::with_opts(
                histogram_opts!(
                    "lean_state_transition_attestations_processing_time_seconds",
                    " Time taken to process attestations",
                    vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
                ),
            )?,

            // Validator metrics
            lean_validators_count: IntGauge::new(
                "lean_validators_count",
                "Number of validators managed by a node",
            )?,

            // Network Metrics
            lean_connected_peers: IntGaugeVec::new(
                opts!("lean_connected_peers", "Number of connected peers",),
                &["client"],
            )?,
            lean_peer_connection_events_total: IntCounterVec::new(
                opts!(
                    "lean_peer_connection_events_total",
                    "Total number of peer connection events",
                ),
                &["direction", "result"],
            )?,
            lean_peer_disconnection_events_total: IntCounterVec::new(
                opts!(
                    "lean_peer_disconnection_events_total",
                    "Total number of peer disconnection events",
                ),
                &["direction", "reason"],
            )?,

            lean_gossip_signatures: IntGauge::new(
                "lean_gossip_signatures",
                "Number of gossip signatures in fork-choice store",
            )?,
            lean_latest_new_aggregated_payloads: IntGauge::new(
                "lean_latest_new_aggregated_payloads",
                "Number of new aggregated payload items",
            )?,
            lean_latest_known_aggregated_payloads: IntGauge::new(
                "lean_latest_known_aggregated_payloads",
                "Number of known aggregated payload items",
            )?,
            lean_committee_signatures_aggregation_time_seconds: Histogram::with_opts(
                histogram_opts!(
                    "lean_committee_signatures_aggregation_time_seconds",
                    "Time taken to aggregate committee signatures",
                    vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0]
                ),
            )?,

            lean_is_aggregator: IntGauge::new(
                "lean_is_aggregator",
                "Validator's is_aggregator status (1=true, 0=false)",
            )?,

            lean_attestation_committee_subnet: IntGauge::new(
                "lean_attestation_committee_subnet",
                "Node's attestation committee subnet",
            )?,
            lean_attestation_committee_count: IntGauge::new(
                "lean_attestation_committee_count",
                "Number of attestation committees (ATTESTATION_COMMITTEE_COUNT)",
            )?,

            // OOM Detection Metrics
            lean_attestation_data_by_root: IntGauge::new(
                "lean_attestation_data_by_root",
                "Number of entries in attestation_data_by_root secondary index",
            )?,
            lean_pending_fetch_roots: IntGauge::new(
                "lean_pending_fetch_roots",
                "Block roots queued for BlocksByRoot fetch (missing-block backlog)",
            )?,
            lean_block_cache_size: IntGauge::new(
                "lean_block_cache_size",
                "Orphan blocks in backfill BlockCache (hard cap 1024)",
            )?,
            lean_slots_behind: IntGauge::new(
                "lean_slots_behind",
                "Current slot minus head slot — backfill depth and primary OOM risk indicator",
            )?,
            lean_fork_choice_known_attestations: IntGauge::new(
                "lean_fork_choice_known_attestations",
                "Validators with known attestations in the fork-choice store",
            )?,
            lean_fork_choice_new_attestations: IntGauge::new(
                "lean_fork_choice_new_attestations",
                "Validators with new gossip attestations in the fork-choice store",
            )?,
            lean_xmss_verify_skipped_total: IntCounter::new(
                "lean_xmss_verify_skipped_total",
                "XMSS verifications skipped (signature already cached) — root cause 4 indicator",
            )?,
        })
    }

    pub fn register_with_default_metrics(&self) -> Result<()> {
        let default_registry = prometheus::default_registry();

        default_registry.register(Box::new(self.lean_node_info.clone()))?;
        default_registry.register(Box::new(self.lean_node_start_time_seconds.clone()))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_attestation_signatures_total.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_attestation_signatures_valid_total.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_attestation_signatures_invalid_total
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_attestation_signing_time_seconds.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_attestation_verification_time_seconds
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_aggregated_signatures_total.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_attestations_in_aggregated_signatures_total
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_aggregated_signatures_building_time_seconds
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_aggregated_signatures_verification_time_seconds
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_aggregated_signatures_valid_total.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_aggregated_signatures_invalid_total.clone(),
        ))?;
        default_registry.register(Box::new(self.lean_head_slot.clone()))?;
        default_registry.register(Box::new(self.lean_current_slot.clone()))?;
        default_registry.register(Box::new(self.lean_safe_target_slot.clone()))?;
        default_registry.register(Box::new(
            self.lean_fork_choice_block_processing_time_seconds.clone(),
        ))?;
        default_registry.register(Box::new(self.lean_attestations_valid_total.clone()))?;
        default_registry.register(Box::new(self.lean_attestations_invalid_total.clone()))?;
        default_registry.register(Box::new(
            self.lean_attestation_validation_time_seconds.clone(),
        ))?;
        default_registry.register(Box::new(self.lean_fork_choice_reorgs_total.clone()))?;
        default_registry.register(Box::new(self.lean_fork_choice_reorg_depth.clone()))?;
        default_registry.register(Box::new(self.lean_latest_justified_slot.clone()))?;
        default_registry.register(Box::new(self.lean_latest_finalized_slot.clone()))?;
        default_registry.register(Box::new(self.lean_finalizations_total.clone()))?;
        default_registry.register(Box::new(self.lean_state_transition_time_seconds.clone()))?;
        default_registry.register(Box::new(
            self.lean_state_transition_slots_processed_total.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_state_transition_slots_processing_time_seconds
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_state_transition_block_processing_time_seconds
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_state_transition_attestations_processed_total
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_state_transition_attestations_processing_time_seconds
                .clone(),
        ))?;
        default_registry.register(Box::new(self.lean_validators_count.clone()))?;
        default_registry.register(Box::new(self.lean_connected_peers.clone()))?;
        default_registry.register(Box::new(self.lean_peer_connection_events_total.clone()))?;
        default_registry.register(Box::new(self.lean_peer_disconnection_events_total.clone()))?;

        // Additional Fork-Choice Metrics
        default_registry.register(Box::new(self.lean_gossip_signatures.clone()))?;
        default_registry.register(Box::new(self.lean_latest_new_aggregated_payloads.clone()))?;
        default_registry.register(Box::new(self.lean_latest_known_aggregated_payloads.clone()))?;
        default_registry.register(Box::new(
            self.lean_committee_signatures_aggregation_time_seconds
                .clone(),
        ))?;

        default_registry.register(Box::new(self.lean_is_aggregator.clone()))?;

        default_registry.register(Box::new(self.lean_attestation_committee_subnet.clone()))?;
        default_registry.register(Box::new(self.lean_attestation_committee_count.clone()))?;

        // OOM Detection Metrics
        default_registry.register(Box::new(self.lean_attestation_data_by_root.clone()))?;
        default_registry.register(Box::new(self.lean_pending_fetch_roots.clone()))?;
        default_registry.register(Box::new(self.lean_block_cache_size.clone()))?;
        default_registry.register(Box::new(self.lean_slots_behind.clone()))?;
        default_registry.register(Box::new(self.lean_fork_choice_known_attestations.clone()))?;
        default_registry.register(Box::new(self.lean_fork_choice_new_attestations.clone()))?;
        default_registry.register(Box::new(self.lean_xmss_verify_skipped_total.clone()))?;

        Ok(())
    }

    pub fn set_client_version(&self, name: String, version: String) {
        self.lean_node_info
            .with_label_values(&[name, version])
            .set(1.0);
    }

    pub fn set_start_time(&self, timestamp: SystemTime) -> Result<()> {
        let timestamp = timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .context("failed to calculate timestamp")?
            .as_secs()
            .try_into()
            .context("sorry, grandine support ended ~292 billion years ago")?;
        self.lean_node_start_time_seconds.set(timestamp);

        Ok(())
    }

    /// Increments successfull peer connection event count metric.
    pub fn register_peer_connection_success(&self, is_inbound: bool) -> Result<()> {
        let direction = if is_inbound { "inbound" } else { "outbound" };
        let metric = self
            .lean_peer_connection_events_total
            .get_metric_with_label_values(&[direction, "success"])?;
        metric.inc();
        Ok(())
    }

    /// Increments peer connection failure event count metric.
    pub fn register_peer_connection_failure(&self, is_inbound: bool) -> Result<()> {
        let direction = if is_inbound { "inbound" } else { "outbound" };
        let metric = self
            .lean_peer_connection_events_total
            .get_metric_with_label_values(&[direction, "failure"])?;
        metric.inc();
        Ok(())
    }

    /// Increments peer connection timeout event count metric.
    pub fn register_peer_connection_timeout(&self, is_inbound: bool) -> Result<()> {
        let direction = if is_inbound { "inbound" } else { "outbound" };
        let metric = self
            .lean_peer_connection_events_total
            .get_metric_with_label_values(&[direction, "timeout"])?;
        metric.inc();
        Ok(())
    }

    pub fn register_peer_disconnect(
        &self,
        is_inbound: bool,
        reason: DisconnectReason,
    ) -> Result<()> {
        let direction = if is_inbound { "inbound" } else { "outbound" };
        let reason = match reason {
            DisconnectReason::Timeout => "timeout",
            DisconnectReason::RemoteClose => "remote_close",
            DisconnectReason::LocalClose => "local_close",
            DisconnectReason::Error => "error",
        };
        let metric = self
            .lean_peer_disconnection_events_total
            .get_metric_with_label_values(&[direction, reason])?;

        metric.inc();

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum DisconnectReason {
    Timeout,
    RemoteClose,
    LocalClose,
    Error,
}
