use axum::{Router, routing::get};

use crate::{
    config::HttpServerConfig,
    handlers::{self, SharedStore},
};

pub fn normal_routes(config: &HttpServerConfig, store: SharedStore) -> Router {
    Router::new()
        .route("/lean/v0/health", get(handlers::health))
        .route("/lean/v0/states/finalized", get(handlers::states_finalized))
        .route(
            "/lean/v0/checkpoints/justified",
            get(handlers::checkpoints_justified),
        )
        .route("/lean/v0/fork_choice", get(handlers::fork_choice))
        .with_state(store)
}
