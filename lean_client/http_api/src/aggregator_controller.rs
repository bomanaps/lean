/// Runtime controller for the node's aggregator role.
///
/// Exposes get/set operations over the shared `is_aggregator` flag so the
/// admin API can rotate aggregator duties across nodes without restarting.
///
/// Toggles are serialized under a `tokio::sync::Mutex` so concurrent admin
/// requests cannot leave the store and validator service disagreeing on the
/// current role.
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::info;
use validator::ValidatorService;

use metrics::METRICS;

use crate::handlers::SharedStore;

/// Shared handle wrapped by [`SharedController`] and passed into axum handlers via `State`.
pub type AggregatorControllerHandle = Arc<AggregatorController>;

/// Shared controller passed into axum handlers via `State`.
pub type SharedController = Option<AggregatorControllerHandle>;

/// Runtime control over the node's aggregator role.
///
/// Operators toggle the flag to rotate aggregation duties across nodes when
/// an active aggregator becomes unhealthy, without restarting the node.
///
/// The spec-level semantics are unchanged: the store reads `is_aggregator`
/// on each gossip event and each tick, so flipping the flag takes effect
/// from the next event or tick onward.
pub struct AggregatorController {
    /// Store whose flag gates gossip-side aggregator behaviour.
    store: SharedStore,

    /// Validator service whose flag drives aggregation duty execution.
    /// `None` when the node has no validator identity.
    validator_service: Option<Arc<ValidatorService>>,

    /// Serializes concurrent toggle requests from admin API handlers.
    lock: Mutex<()>,
}

impl AggregatorController {
    /// Create a new controller.
    ///
    /// # Arguments
    /// * `store` — shared forkchoice store
    /// * `validator_service` — optional validator service
    pub fn new(store: SharedStore, validator_service: Option<Arc<ValidatorService>>) -> Self {
        Self {
            store,
            validator_service,
            lock: Mutex::new(()),
        }
    }

    /// Return whether the node is currently acting as aggregator.
    ///
    /// Reads the live flag from the store (source of truth).
    pub fn is_enabled(&self) -> bool {
        self.store.read().is_aggregator
    }

    /// Update the aggregator role and return the previous value.
    ///
    /// The store and validator service are updated together under the mutex
    /// so both views remain consistent from any observer's perspective.
    ///
    /// # Arguments
    /// * `enabled` — desired aggregator state
    ///
    /// # Returns
    /// Aggregator state prior to the update.
    pub async fn set_enabled(&self, enabled: bool) -> bool {
        let _guard = self.lock.lock().await;

        let previous = self.store.read().is_aggregator;
        self.store.write().is_aggregator = enabled;

        if let Some(vs) = &self.validator_service {
            vs.set_is_aggregator(enabled);
        }

        METRICS
            .get()
            .map(|m| m.lean_is_aggregator.set(if enabled { 1 } else { 0 }));

        if previous != enabled {
            info!(
                is_aggregator = enabled,
                "Aggregator role {} via admin API",
                if enabled { "activated" } else { "deactivated" },
            );
        }

        previous
    }
}
