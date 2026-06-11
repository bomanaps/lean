use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use containers::{SignedAggregatedAttestation, Slot};
use dedicated_executor::DedicatedExecutor;
use fork_choice::store::Store;
use metrics::METRICS;
use parking_lot::RwLock;
use ssz::H256;
use tokio::sync::{mpsc, watch};
use validator::{ValidatorService, snapshot_aggregation_inputs};

const AGGREGATION_DEADLINE: Duration = Duration::from_millis(750);

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
        cpu_snark_executor: Arc<DedicatedExecutor>,
    ) -> Self {
        let (agg_tx, mut agg_rx) = watch::channel::<Option<u64>>(None);
        let (res_tx, res_rx) = mpsc::channel::<(
            u64,
            Option<(Vec<SignedAggregatedAttestation>, HashSet<H256>)>,
        )>(4);

        let vs_for_worker = vs.clone();

        tokio::spawn(async move {
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

                let snapshot_start = Instant::now();
                let snapshot = {
                    let guard = store.read();
                    snapshot_aggregation_inputs(&guard)
                };
                let snapshot_elapsed = snapshot_start.elapsed();

                let Some(snapshot) = snapshot else {
                    METRICS
                        .get()
                        .map(|m| m.lean_aggregation_in_flight_snapshots.dec());
                    if res_tx.send((slot, None)).await.is_err() {
                        break;
                    }
                    continue;
                };

                METRICS.get().map(|m| {
                    m.lean_aggregation_snapshot_clone_seconds
                        .observe(snapshot_elapsed.as_secs_f64());
                    let entries: usize = snapshot
                        .jobs
                        .iter()
                        .map(|j| j.children.len() + j.raw_ids.len() + j.accepted_child_ids.len())
                        .sum::<usize>()
                        + snapshot.jobs.len();
                    m.lean_aggregation_snapshot_size_entries
                        .observe(entries as f64);
                });

                let cancel = Arc::new(AtomicBool::new(false));
                let cancel_for_timer = cancel.clone();
                let deadline_handle = tokio::spawn(async move {
                    tokio::time::sleep(AGGREGATION_DEADLINE).await;
                    cancel_for_timer.store(true, Ordering::Relaxed);
                });

                let cancel_for_worker = cancel.clone();
                let snark_exec = cpu_snark_executor.clone();
                let job = snark_exec.spawn(async move {
                    vs.maybe_aggregate(&snapshot, Slot(slot), log_rate, &cancel_for_worker)
                });
                let result = job.await.unwrap_or(None);

                deadline_handle.abort();

                METRICS
                    .get()
                    .map(|m| m.lean_aggregation_in_flight_snapshots.dec());
                if res_tx.send((slot, result)).await.is_err() {
                    break;
                }
            }
        });

        Self { vs, agg_tx, res_rx }
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

    /// Awaits the next completed aggregation result. Returns `None` only when
    /// the worker has shut down. Used as a `tokio::select!` arm on the chain
    /// task so results land in `latest_new_aggregated_payloads` the moment the
    /// SNARK finishes — not on the next 800 ms tick.
    pub async fn recv(
        &mut self,
    ) -> Option<(
        u64,
        Option<(Vec<SignedAggregatedAttestation>, HashSet<H256>)>,
    )> {
        self.res_rx.recv().await
    }
}
