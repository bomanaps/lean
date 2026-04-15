use std::collections::HashSet;
use std::sync::Arc;

use containers::{SignedAggregatedAttestation, Slot};
use fork_choice::store::Store;
use ssz::H256;
use tokio::sync::{mpsc, watch};
use tokio::task;
use validator::ValidatorService;

/// Aggregation service that decouples XMSS aggregation from the chain task.
///
/// Owns a `watch` channel for receiving store snapshots (always latest value)
/// and an `mpsc` channel for returning results.  The caller drives the service
/// through [`trigger`] and [`poll`] instead of managing raw channel ends.
pub struct AggregationService {
    agg_tx: watch::Sender<Option<(u64, Store)>>,
    res_rx: mpsc::Receiver<(
        u64,
        Option<(Vec<SignedAggregatedAttestation>, HashSet<H256>)>,
    )>,
}

impl AggregationService {
    /// Creates the service and spawns the background aggregation task.
    pub fn new(vs: Arc<ValidatorService>, log_rate: usize) -> Self {
        let (agg_tx, mut agg_rx) = watch::channel::<Option<(u64, Store)>>(None);
        let (res_tx, res_rx) = mpsc::channel::<(
            u64,
            Option<(Vec<SignedAggregatedAttestation>, HashSet<H256>)>,
        )>(4);

        task::spawn(async move {
            loop {
                if agg_rx.changed().await.is_err() {
                    break; // sender dropped — chain task shut down
                }
                let Some((slot, snapshot)) = agg_rx.borrow_and_update().clone() else {
                    continue;
                };
                let vs = vs.clone();
                let result = task::spawn_blocking(move || {
                    vs.maybe_aggregate(&snapshot, Slot(slot), log_rate)
                })
                .await
                .unwrap_or(None);
                if res_tx.send((slot, result)).await.is_err() {
                    break; // chain task dropped — shut down
                }
            }
        });

        Self { agg_tx, res_rx }
    }

    /// Triggers aggregation for the given slot with the provided store snapshot.
    ///
    /// Uses watch semantics: if a previous trigger has not been consumed yet,
    /// it is overwritten with the latest value so XMSS always works on the
    /// most recent state.
    pub fn trigger(&self, slot: u64, snapshot: Store) {
        let _ = self.agg_tx.send(Some((slot, snapshot)));
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
