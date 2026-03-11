use axum::{Router, routing::get};
use metrics::metrics_module;

use crate::{
    config::HttpServerConfig,
    handlers::{self, SharedStore},
};

pub fn normal_routes(
    config: &HttpServerConfig,
    genesis_time: u64,
    store: Option<SharedStore>,
) -> Router {
    let mut router = Router::new();

    if config.metrics_enabled() {
        router = router.merge(metrics_module(config.metrics.clone(), genesis_time));
    }

    if let Some(store) = store {
        let lean_routes = Router::new()
            .route("/lean/v0/health", get(handlers::health))
            .route("/lean/v0/states/finalized", get(handlers::states_finalized))
            .route(
                "/lean/v0/checkpoints/justified",
                get(handlers::checkpoints_justified),
            )
            .route("/lean/v0/fork_choice", get(handlers::fork_choice))
            .with_state(store);

        router = router.merge(lean_routes);
    }

    router
}
