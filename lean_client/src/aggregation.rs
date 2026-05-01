use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use containers::{SignedAggregatedAttestation, Slot};
use fork_choice::store::Store;
use metrics::METRICS;
use parking_lot::RwLock;
use ssz::H256;
use tokio::sync::{mpsc, watch};
use tokio::task;
use validator::ValidatorService;

/// Aggregation service that decouples XMSS aggregation from the chain task.
///
/// Owns:
/// - a `watch` channel carrying just the slot for which to aggregate (always
///   latest value);
/// - a shared `Arc<RwLock<Store>>` that the worker reads from briefly to clone
///   a snapshot on its own thread (V2 — keeps the chain task off the deep-clone);
/// - an `mpsc` channel for returning results.
///
/// The caller drives the service through [`trigger`] and [`poll`] instead of
/// managing raw channel ends.
pub struct AggregationService {
    vs: Arc<ValidatorService>,
    agg_tx: watch::Sender<Option<u64>>,
    res_rx: mpsc::Receiver<(
        u64,
        Option<(Vec<SignedAggregatedAttestation>, HashSet<H256>)>,
    )>,
}

impl AggregationService {
    /// Creates the service and spawns the background aggregation task.
    ///
    /// The worker holds an `Arc<RwLock<Store>>` reference so it can read +
    /// clone the snapshot on its own thread instead of forcing the chain task
    /// to do the deep-clone.
    pub fn new(
        vs: Arc<ValidatorService>,
        store: Arc<RwLock<Store>>,
        log_rate: usize,
    ) -> Self {
        let (agg_tx, mut agg_rx) = watch::channel::<Option<u64>>(None);
        let (res_tx, res_rx) = mpsc::channel::<(
            u64,
            Option<(Vec<SignedAggregatedAttestation>, HashSet<H256>)>,
        )>(4);

        let vs_for_worker = vs.clone();

        task::spawn(async move {
            loop {
                if agg_rx.changed().await.is_err() {
                    break; // sender dropped — chain task shut down
                }
                let Some(slot) = *agg_rx.borrow_and_update() else {
                    continue;
                };
                let vs = vs_for_worker.clone();
                let store = store.clone();
                METRICS
                    .get()
                    .map(|m| m.lean_aggregation_in_flight_snapshots.inc());
                let result = task::spawn_blocking(move || {
                    // Clone on this worker thread: brief read lock held only for
                    // the duration of the clone, then released before XMSS work.
                    let clone_start = Instant::now();
                    let snapshot = {
                        let guard = store.read();
                        guard.clone()
                    };
                    let clone_elapsed = clone_start.elapsed();

                    METRICS.get().map(|m| {
                        m.lean_aggregation_snapshot_clone_seconds
                            .observe(clone_elapsed.as_secs_f64());
                        let entries = snapshot.blocks.len()
                            + snapshot.states.len()
                            + snapshot.gossip_signatures.len()
                            + snapshot.latest_known_aggregated_payloads.len()
                            + snapshot.latest_new_aggregated_payloads.len()
                            + snapshot.attestation_data_by_root.len();
                        m.lean_aggregation_snapshot_size_entries
                            .observe(entries as f64);
                    });

                    vs.maybe_aggregate(&snapshot, Slot(slot), log_rate)
                })
                .await
                .unwrap_or(None);
                METRICS
                    .get()
                    .map(|m| m.lean_aggregation_in_flight_snapshots.dec());
                if res_tx.send((slot, result)).await.is_err() {
                    break; // chain task dropped — shut down
                }
            }
        });

        Self {
            vs,
            agg_tx,
            res_rx,
        }
    }

    /// Returns true if this node should aggregate for the given slot. Used by
    /// the chain task to gate the trigger so non-aggregator nodes never enqueue
    /// snapshot work.
    pub fn is_aggregator_for_slot(&self, slot: Slot) -> bool {
        self.vs.is_aggregator_for_slot(slot)
    }

    /// Triggers aggregation for the given slot. The worker reads + clones the
    /// store on its own thread.
    ///
    /// Watch semantics: if a previous trigger has not been consumed yet, it is
    /// overwritten with the latest slot so XMSS always works on the most recent
    /// trigger.
    pub fn trigger(&self, slot: u64) {
        let _ = self.agg_tx.send(Some(slot));
    }

    /// Returns the next completed aggregation result, or `None` if none is ready.
    pub fn poll(
        &mut self,
    ) -> Option<(
        u64,
        Option<(Vec<SignedAggregatedAttestation>, HashSet<H256>)>,
    )> {
        self.res_rx.try_recv().ok()
    }
}
