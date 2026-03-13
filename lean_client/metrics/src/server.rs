use std::{
    error::Error as StdError,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Error as AnyhowError, Result};
use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use clap::Args;
use futures::{FutureExt as _, TryFutureExt as _};
use http_api_utils::ApiError;
use prometheus::TextEncoder;
use thiserror::Error;
use tokio::net::TcpListener;
use tower_http::cors::AllowOrigin;
use tracing::info;

use crate::METRICS;

const DEFAULT_METRICS_PORT: u16 = 9090;

#[derive(Clone, Debug, Args)]
pub struct MetricsServerConfig {
    #[arg(long = "metrics-timeout", default_value_t = Self::default().timeout, requires = "metrics_enabled")]
    timeout: u64,

    #[arg(long = "metrics")]
    metrics_enabled: bool,

    #[clap(long = "metrics-address", default_value_t = Self::default().metrics_address)]
    metrics_address: IpAddr,

    #[clap(long = "metrics-port", default_value_t = Self::default().metrics_port)]
    metrics_port: u16,
}

impl Default for MetricsServerConfig {
    fn default() -> Self {
        Self {
            metrics_enabled: false,
            timeout: Duration::from_secs(1000)
                .as_millis()
                .try_into()
                .expect("should fit into u64"),
            metrics_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            metrics_port: DEFAULT_METRICS_PORT,
        }
    }
}

impl MetricsServerConfig {
    pub fn enabled(&self) -> bool {
        self.metrics_enabled
    }

    pub fn address(&self) -> SocketAddr {
        (self.metrics_address, self.metrics_port).into()
    }

    async fn listener(&self) -> Result<TcpListener> {
        TcpListener::bind(self.address()).await.map_err(Into::into)
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("internal error")]
    Internal(#[from] AnyhowError),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

impl ApiError for Error {
    fn sources(&self) -> impl Iterator<Item = &dyn StdError> {
        let mut error: Option<&dyn StdError> = Some(self);

        core::iter::from_fn(move || {
            let source = error?.source();
            core::mem::replace(&mut error, source)
        })
    }
}

fn metrics_module(config: MetricsServerConfig, genesis_time: u64) -> Router {
    let router = Router::new()
        .route("/metrics", get(get_metrics))
        .with_state(genesis_time);

    let router = http_api_utils::extend_router_with_middleware::<Error>(
        router,
        Some(Duration::from_millis(config.timeout)),
        AllowOrigin::any(),
        None,
    );

    router
}

pub async fn run_server(config: MetricsServerConfig, genesis_time: u64) -> Result<()> {
    let router = Router::new().merge(metrics_module(config.clone(), genesis_time));

    let listener = config
        .listener()
        .await
        .context("failed to start http server")?;

    let service = router.into_make_service_with_connect_info::<SocketAddr>();

    let serve_requests = axum::serve(listener, service)
        .into_future()
        .map_err(AnyhowError::new);

    info!("metrics server listening on {}", config.address());

    serve_requests.fuse().await
}

/// `GET /metrics`
async fn get_metrics(State(genesis_time): State<u64>) -> Result<String, Error> {
    let mut buffer = String::new();

    METRICS.get().map(|metrics| {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let since_genesis = time.saturating_sub(genesis_time * 1000);
        // TODO: 4000 should be replaced with constant MILLIS_PER_SLOT
        let slot = since_genesis / 4000;

        metrics.lean_current_slot.set(slot as i64);
    });

    TextEncoder::new()
        .encode_utf8(prometheus::gather().as_slice(), &mut buffer)
        .map_err(AnyhowError::new)?;

    Ok(buffer)
}
