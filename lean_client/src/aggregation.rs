use std::collections::HashSet;
use std::sync::Arc;

use containers::{SignedAggregatedAttestation, Slot};
use fork_choice::store::Store;
use ssz::H256;
use tokio::sync::{mpsc, watch};
use tokio::task;
use validator::ValidatorService;

/// Spawns the aggregation task that runs `maybe_aggregate` off the chain task thread.
///
/// Receives store snapshots via `agg_rx` (watch channel — always latest value),
/// runs XMSS aggregation in a blocking thread, and sends results back via `res_tx`.
pub fn spawn(
    vs: Arc<ValidatorService>,
    mut agg_rx: watch::Receiver<Option<(u64, Store)>>,
    res_tx: mpsc::Sender<(u64, Option<(Vec<SignedAggregatedAttestation>, HashSet<H256>)>)>,
    log_rate: usize,
) {
    task::spawn(async move {
        loop {
            if agg_rx.changed().await.is_err() {
                break; // sender dropped — chain task shut down
            }
            let Some((slot, snapshot)) = agg_rx.borrow_and_update().clone() else {
                continue;
            };
            let vs = vs.clone();
            let result =
                task::spawn_blocking(move || vs.maybe_aggregate(&snapshot, Slot(slot), log_rate))
                    .await
                    .unwrap_or(None);
            if res_tx.send((slot, result)).await.is_err() {
                break; // chain task dropped — shut down
            }
        }
    });
}
