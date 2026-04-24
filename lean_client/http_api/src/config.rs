use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::Result;
use clap::Args;
use tokio::net::TcpListener;

const DEFAULT_HTTP_PORT: u16 = 8080;

#[derive(Debug, Clone, Args)]
pub struct HttpServerConfig {
    #[clap(long = "http-address", default_value_t = HttpServerConfig::default().http_address)]
    http_address: IpAddr,

    #[clap(long = "http-port", default_value_t = HttpServerConfig::default().http_port)]
    http_port: u16,
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
            http_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            http_port: DEFAULT_HTTP_PORT,
        }
    }
}

impl HttpServerConfig {
    pub(crate) async fn listener(&self) -> Result<TcpListener> {
        TcpListener::bind(self.address()).await.map_err(Into::into)
    }

    pub fn address(&self) -> SocketAddr {
        (self.http_address, self.http_port).into()
    }
}
