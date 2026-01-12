pub mod client;
pub mod config;
pub mod connection;
pub mod metrics;
pub mod pool;
pub mod transport;

pub use client::SocketClient;
pub use config::{RetryConfig, TimeoutConfig};
pub use connection::{
    create_client_handler, create_server_handler, MultiplexedConnectionHandler,
    ServerCommandHandler,
};
pub use metrics::{ConnectionMetrics, HistogramData, MetricsTracker, RequestRateTracker};
pub use pool::{ConnectionStats, SocketPool};
pub use transport::{SocketConnector, SocketStream};
