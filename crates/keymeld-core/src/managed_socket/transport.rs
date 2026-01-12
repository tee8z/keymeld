use crate::KeyMeldError;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_vsock::{VsockAddr, VsockStream};
use tracing::{debug, error};

/// Connector for establishing socket connections.
/// Supports both vsock (for AWS Nitro Enclaves) and TCP (for K8s/simulation).
#[derive(Clone, Debug)]
pub enum SocketConnector {
    /// Connect via vsock (AWS Nitro Enclave mode)
    Vsock { cid: u32, port: u32 },
    /// Connect via TCP (K8s/simulation mode)
    Tcp { host: String, port: u16 },
}

impl SocketConnector {
    /// Create a new vsock connector
    pub fn vsock(cid: u32, port: u32) -> Self {
        Self::Vsock { cid, port }
    }

    /// Create a new TCP connector
    pub fn tcp(host: impl Into<String>, port: u16) -> Self {
        Self::Tcp {
            host: host.into(),
            port,
        }
    }

    /// Connect to the remote endpoint with the specified timeout
    pub async fn connect(&self, connect_timeout: Duration) -> Result<SocketStream, KeyMeldError> {
        match self {
            Self::Vsock { cid, port } => {
                debug!("Connecting via vsock to CID {}:{}", cid, port);
                let addr = VsockAddr::new(*cid, *port);
                let stream = timeout(connect_timeout, VsockStream::connect(addr))
                    .await
                    .map_err(|_| {
                        error!(
                            "Timeout connecting to vsock {}:{} after {:?}",
                            cid, port, connect_timeout
                        );
                        KeyMeldError::EnclaveError(format!(
                            "Timeout connecting to vsock {}:{} after {:?}",
                            cid, port, connect_timeout
                        ))
                    })?
                    .map_err(|e| {
                        error!("Failed to connect to vsock {}:{}: {}", cid, port, e);
                        KeyMeldError::EnclaveError(format!(
                            "Failed to connect to vsock {}:{}: {}",
                            cid, port, e
                        ))
                    })?;
                debug!("Connected via vsock to CID {}:{}", cid, port);
                Ok(SocketStream::Vsock(stream))
            }
            Self::Tcp { host, port } => {
                debug!("Connecting via TCP to {}:{}", host, port);
                let addr = format!("{}:{}", host, port);
                let stream = timeout(connect_timeout, TcpStream::connect(&addr))
                    .await
                    .map_err(|_| {
                        error!(
                            "Timeout connecting to TCP {} after {:?}",
                            addr, connect_timeout
                        );
                        KeyMeldError::EnclaveError(format!(
                            "Timeout connecting to TCP {} after {:?}",
                            addr, connect_timeout
                        ))
                    })?
                    .map_err(|e| {
                        error!("Failed to connect to TCP {}: {}", addr, e);
                        KeyMeldError::EnclaveError(format!(
                            "Failed to connect to TCP {}: {}",
                            addr, e
                        ))
                    })?;
                debug!("Connected via TCP to {}:{}", host, port);
                Ok(SocketStream::Tcp(stream))
            }
        }
    }

    /// Get a human-readable address string for logging
    pub fn address_string(&self) -> String {
        match self {
            Self::Vsock { cid, port } => format!("vsock://{}:{}", cid, port),
            Self::Tcp { host, port } => format!("tcp://{}:{}", host, port),
        }
    }
}

/// A unified stream type that wraps either a VsockStream or TcpStream.
/// Implements AsyncRead and AsyncWrite by delegating to the inner stream.
pub enum SocketStream {
    Vsock(VsockStream),
    Tcp(TcpStream),
}

impl AsyncRead for SocketStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            SocketStream::Vsock(stream) => Pin::new(stream).poll_read(cx, buf),
            SocketStream::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for SocketStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            SocketStream::Vsock(stream) => Pin::new(stream).poll_write(cx, buf),
            SocketStream::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            SocketStream::Vsock(stream) => Pin::new(stream).poll_flush(cx),
            SocketStream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            SocketStream::Vsock(stream) => Pin::new(stream).poll_shutdown(cx),
            SocketStream::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_connector_vsock_creation() {
        let connector = SocketConnector::vsock(16, 5000);
        assert_eq!(connector.address_string(), "vsock://16:5000");
    }

    #[test]
    fn test_socket_connector_tcp_creation() {
        let connector = SocketConnector::tcp("localhost", 5000);
        assert_eq!(connector.address_string(), "tcp://localhost:5000");
    }

    #[test]
    fn test_socket_connector_clone() {
        let connector = SocketConnector::tcp("example.com", 8080);
        let cloned = connector.clone();
        assert_eq!(connector.address_string(), cloned.address_string());
    }
}
