use super::config::TimeoutConfig;
use crate::managed_vsock::metrics::ConnectionMetrics;
use anyhow::{anyhow, Result};
use bincode;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::{
    future::Future,
    io::ErrorKind,
    pin::Pin,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Instant,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::mpsc,
    time::timeout,
};
use tokio_vsock::VsockStream;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::metrics::{MetricsTracker, RequestRateTracker};

// Type aliases to fix clippy type complexity warnings
type RequestWithResponse<C, R> = (Request<C>, mpsc::Sender<R>);
type RequestSender<C, R> = mpsc::Sender<RequestWithResponse<C, R>>;

// Application-level message framing protocol:
// Each message is prefixed with a 4-byte big-endian u32 indicating the message length.
// This is NOT a VSockets protocol requirement - VSockets are just the transport layer.
// We use this for reliable message boundaries over the stream.
const FRAME_HEADER_SIZE: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection is actively processing requests
    Active,
    /// Connection is idle but ready
    Idle,
    /// Connection has failed and needs reconnection
    Failed,
    /// Connection is being established
    Connecting,
    /// Connection is gracefully shutting down
    Disconnecting,
}

pub enum ConnectionHandler<C, R> {
    Server(ServerHandler<C, R>),
    Client(ClientHandler<C, R>),
}

impl<C, R> ConnectionHandler<C, R>
where
    C: Clone + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize + 'static,
    R: Clone + Send + Sync + serde::Serialize + for<'de> serde::Deserialize<'de> + 'static,
{
    pub async fn handle_connection(
        self,
        stream: VsockStream,
        active_connections: Arc<AtomicU32>,
        request_rate_tracker: Arc<RequestRateTracker>,
        timeout_config: TimeoutConfig,
    ) -> Result<()> {
        match self {
            ConnectionHandler::Server(handler) => {
                handler
                    .handle_connection(
                        stream,
                        active_connections,
                        request_rate_tracker,
                        timeout_config,
                    )
                    .await
            }
            ConnectionHandler::Client(handler) => {
                handler
                    .handle_connection(
                        stream,
                        active_connections,
                        request_rate_tracker,
                        timeout_config,
                    )
                    .await
            }
        }
    }
}

pub struct ServerHandler<C, R> {
    command_handler: Arc<dyn ServerCommandHandler<C, R>>,
    metrics: Arc<MetricsTracker>,
}

impl<C, R> ServerHandler<C, R>
where
    C: Clone + Send + Sync + for<'de> Deserialize<'de> + 'static,
    R: Clone + Send + Sync + Serialize + 'static,
{
    pub fn new(
        command_handler: Arc<dyn ServerCommandHandler<C, R>>,
        metrics: Arc<MetricsTracker>,
    ) -> Self {
        Self {
            command_handler,
            metrics,
        }
    }

    async fn handle_connection(
        self,
        stream: VsockStream,
        active_connections: Arc<AtomicU32>,
        request_rate_tracker: Arc<RequestRateTracker>,
        timeout_config: TimeoutConfig,
    ) -> Result<()> {
        // Increment active connections count
        active_connections.fetch_add(1, Ordering::AcqRel);
        debug!(
            "Server connection established. Active connections: {}",
            active_connections.load(Ordering::Acquire)
        );

        let result = self
            .handle_connection_inner(stream, request_rate_tracker, timeout_config)
            .await;

        // Decrement active connections count
        active_connections.fetch_sub(1, Ordering::AcqRel);
        debug!(
            "Server connection closed. Active connections: {}",
            active_connections.load(Ordering::Acquire)
        );

        result
    }

    async fn handle_connection_inner(
        self,
        stream: VsockStream,
        request_rate_tracker: Arc<RequestRateTracker>,
        timeout_config: TimeoutConfig,
    ) -> Result<()> {
        let (response_tx, response_rx) =
            mpsc::channel::<Response<R>>(timeout_config.max_channel_size);

        // Split stream into separate read/write halves to prevent race conditions
        // when select! cancels a read future while a write is pending
        let (reader, writer) = tokio::io::split(stream);

        // Spawn read task for receiving requests
        let command_handler = self.command_handler.clone();
        let read_rate_tracker = request_rate_tracker.clone();
        let read_timeout = timeout_config.clone();
        let read_response_tx = response_tx.clone();
        let read_task = tokio::spawn(async move {
            Self::handle_server_read_task(
                reader,
                command_handler,
                read_rate_tracker,
                read_timeout,
                read_response_tx,
            )
            .await
        });

        // Spawn write task for sending responses
        let write_timeout = timeout_config.clone();
        let write_task = tokio::spawn(async move {
            Self::handle_server_write_task(writer, response_rx, write_timeout).await
        });

        // Wait for either task to complete (or fail)
        tokio::select! {
            read_result = read_task => {
                match read_result {
                    Ok(Ok(())) => debug!("Server read task completed successfully"),
                    Ok(Err(e)) => error!("Server read task error: {e}"),
                    Err(e) => error!("Server read task panicked: {e}"),
                }
            }
            write_result = write_task => {
                match write_result {
                    Ok(Ok(())) => debug!("Server write task completed successfully"),
                    Ok(Err(e)) => error!("Server write task error: {e}"),
                    Err(e) => error!("Server write task panicked: {e}"),
                }
            }
        }

        debug!("Server connection handler completed successfully");
        Ok(())
    }

    async fn handle_server_read_task(
        mut reader: ReadHalf<VsockStream>,
        command_handler: Arc<dyn ServerCommandHandler<C, R>>,
        request_rate_tracker: Arc<RequestRateTracker>,
        timeout_config: TimeoutConfig,
        response_tx: mpsc::Sender<Response<R>>,
    ) -> Result<()> {
        let mut buffer = vec![0u8; FRAME_HEADER_SIZE];

        loop {
            match Self::read_request_from_reader(&mut reader, &mut buffer, &timeout_config).await {
                Ok(Some(request)) => {
                    Self::spawn_request_handler(
                        &command_handler,
                        &request_rate_tracker,
                        request,
                        response_tx.clone(),
                    );
                }
                Ok(None) => {
                    debug!("Server connection closed by client - ending request processing loop");
                    break;
                }
                Err(e) => {
                    error!("Error reading request: {e}");
                    return Err(e);
                }
            }
        }

        debug!("Server read task completed");
        Ok(())
    }

    async fn handle_server_write_task(
        mut writer: WriteHalf<VsockStream>,
        mut response_rx: mpsc::Receiver<Response<R>>,
        timeout_config: TimeoutConfig,
    ) -> Result<()> {
        while let Some(response) = response_rx.recv().await {
            if let Err(e) =
                Self::send_response_to_writer(&mut writer, response, &timeout_config).await
            {
                error!("Error sending response: {e}");
                return Err(e);
            }
        }

        debug!("Server write task completed - response channel closed");
        Ok(())
    }

    async fn read_request_from_reader(
        reader: &mut ReadHalf<VsockStream>,
        buffer: &mut [u8],
        timeout_config: &TimeoutConfig,
    ) -> Result<Option<Request<C>>> {
        match timeout(
            timeout_config.network_read_timeout(),
            reader.read_exact(buffer),
        )
        .await
        {
            Ok(Ok(_)) => {
                let message_len =
                    u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

                if message_len > timeout_config.max_message_size_bytes {
                    return Err(anyhow!("Message too large: {message_len} bytes"));
                }

                let mut message_buffer = vec![0u8; message_len];
                match timeout(
                    timeout_config.network_read_timeout(),
                    reader.read_exact(&mut message_buffer),
                )
                .await
                {
                    Ok(Ok(_)) => match bincode::deserialize::<Request<C>>(&message_buffer) {
                        Ok(request) => Ok(Some(request)),
                        Err(e) => {
                            error!("Failed to deserialize request: {e}");
                            Err(anyhow!("Failed to deserialize request: {e}"))
                        }
                    },
                    Ok(Err(e)) => Err(anyhow!("Failed to read message body: {e}")),
                    Err(_) => Err(anyhow!("Timeout reading message body")),
                }
            }
            Ok(Err(e)) => {
                if e.kind() == ErrorKind::UnexpectedEof {
                    Ok(None)
                } else {
                    Err(anyhow!("Failed to read message header: {e}"))
                }
            }
            Err(e) => Err(anyhow!("Timeout reading message header: {e}")),
        }
    }

    async fn send_response_to_writer(
        writer: &mut WriteHalf<VsockStream>,
        response: Response<R>,
        timeout_config: &TimeoutConfig,
    ) -> Result<()> {
        let response_data = bincode::serialize(&response)
            .map_err(|e| anyhow!("Failed to serialize response: {e}"))?;

        let length_bytes = (response_data.len() as u32).to_be_bytes();

        timeout(
            timeout_config.network_write_timeout(),
            writer.write_all(&length_bytes),
        )
        .await
        .map_err(|e| anyhow!("Timeout writing response length: {e}"))?
        .map_err(|e| anyhow!("Failed to write response length: {e}"))?;

        timeout(
            timeout_config.network_write_timeout(),
            writer.write_all(&response_data),
        )
        .await
        .map_err(|e| anyhow!("Timeout writing response data: {e}"))?
        .map_err(|e| anyhow!("Failed to write response data: {e}"))?;

        Ok(())
    }

    pub fn get_metrics(&self) -> ConnectionMetrics {
        self.metrics.get_metrics()
    }
}

impl<C, R> ServerHandler<C, R>
where
    C: Clone + Send + Sync + for<'de> Deserialize<'de> + 'static,
    R: Clone + Send + Sync + Serialize + 'static,
{
    fn spawn_request_handler(
        command_handler: &Arc<dyn ServerCommandHandler<C, R>>,
        rate_tracker: &Arc<RequestRateTracker>,
        request: Request<C>,
        response_tx: mpsc::Sender<Response<R>>,
    ) {
        let command_handler = command_handler.clone();
        let rate_tracker = rate_tracker.clone();
        let request_id = request.request_id;
        let command = request.command;

        tokio::spawn(async move {
            let response = match command_handler.handle_command(command).await {
                Ok(response) => response,
                Err(e) => {
                    error!("Error processing request {}: {}", request_id, e);
                    // Return error handling to the implementation
                    return;
                }
            };

            // Record request in the rate tracker and server metrics
            rate_tracker.record_request();

            let response_msg = Response {
                request_id,
                response,
            };

            let send_start = std::time::Instant::now();
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                response_tx.send(response_msg),
            )
            .await
            {
                Ok(Ok(())) => {
                    let send_duration = send_start.elapsed();
                    if send_duration > std::time::Duration::from_millis(100) {
                        warn!(
                            "Slow channel send for request {}: took {:?}",
                            request_id, send_duration
                        );
                    }
                }
                Ok(Err(e)) => {
                    error!("Failed to send response for request {}: {}", request_id, e);
                }
                Err(_) => {
                    error!(
                        "Channel send timeout for request {} after 5s - possible channel deadlock!",
                        request_id
                    );
                }
            }
        });
    }
}

pub struct ClientHandler<C, R> {
    request_rx: mpsc::Receiver<RequestWithResponse<C, R>>,
    metrics: Arc<MetricsTracker>,
}

impl<C, R> ClientHandler<C, R>
where
    C: Clone + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize + 'static,
    R: Clone + Send + Sync + serde::Serialize + for<'de> serde::Deserialize<'de> + 'static,
{
    pub fn new(
        metrics: Arc<MetricsTracker>,
        max_channel_size: usize,
    ) -> (Self, RequestSender<C, R>) {
        let (request_tx, request_rx) = mpsc::channel(max_channel_size);

        info!(
            "Created request channel with capacity {} for client connection",
            max_channel_size
        );

        let handler = Self {
            request_rx,
            metrics,
        };

        (handler, request_tx)
    }

    async fn handle_connection(
        self,
        stream: VsockStream,
        active_connections: Arc<AtomicU32>,
        request_rate_tracker: Arc<RequestRateTracker>,
        timeout_config: TimeoutConfig,
    ) -> Result<()> {
        // Increment active connections count
        active_connections.fetch_add(1, Ordering::AcqRel);
        debug!(
            "Client connection established. Active connections: {}",
            active_connections.load(Ordering::Acquire)
        );

        let result = self
            .handle_connection_inner(stream, request_rate_tracker, timeout_config)
            .await;

        // Decrement active connections count
        active_connections.fetch_sub(1, Ordering::AcqRel);
        debug!(
            "Client connection closed. Active connections: {}",
            active_connections.load(Ordering::Acquire)
        );

        result
    }

    async fn handle_connection_inner(
        self,
        stream: VsockStream,
        request_rate_tracker: Arc<RequestRateTracker>,
        timeout_config: TimeoutConfig,
    ) -> Result<()> {
        let (reader, writer) = tokio::io::split(stream);

        debug!("Starting client connection with read/write tasks");

        // Track pending requests for correlation with latency tracking
        let pending_requests: Arc<DashMap<u128, (mpsc::Sender<R>, Instant)>> =
            Arc::new(DashMap::new());

        // Spawn read task for receiving responses
        let read_pending = pending_requests.clone();
        let read_timeout = timeout_config.clone();
        let read_metrics = self.metrics.clone();
        let read_rate_tracker = request_rate_tracker.clone();
        let read_task = tokio::spawn(async move {
            Self::handle_read_task(
                reader,
                read_pending,
                read_timeout,
                read_metrics,
                read_rate_tracker,
            )
            .await
        });

        // Spawn write task for sending requests
        let write_pending = pending_requests.clone();
        let write_timeout = timeout_config.clone();
        let write_metrics = self.metrics.clone();
        let write_rate_tracker = request_rate_tracker.clone();
        let request_rx = self.request_rx;
        let write_task = tokio::spawn(async move {
            Self::handle_write_task(
                writer,
                request_rx,
                write_pending,
                write_timeout,
                write_metrics,
                write_rate_tracker,
            )
            .await
        });

        // Wait for either task to complete (or fail)
        tokio::select! {
            read_result = read_task => {
                match read_result {
                    Ok(Ok(())) => debug!("Client read task completed successfully"),
                    Ok(Err(e)) => error!("Client read task error: {e}"),
                    Err(e) => error!("Client read task panicked: {e}"),
                }
            }
            write_result = write_task => {
                match write_result {
                    Ok(Ok(())) => debug!("Client write task completed successfully"),
                    Ok(Err(e)) => error!("Client write task error: {e}"),
                    Err(e) => error!("Client write task panicked: {e}"),
                }
            }
        }

        Ok(())
    }

    async fn handle_read_task(
        mut reader: ReadHalf<VsockStream>,
        pending_requests: Arc<DashMap<u128, (mpsc::Sender<R>, Instant)>>,
        timeout_config: TimeoutConfig,
        metrics: Arc<MetricsTracker>,
        request_rate_tracker: Arc<RequestRateTracker>,
    ) -> Result<()> {
        let mut buffer = vec![0u8; FRAME_HEADER_SIZE];

        loop {
            // Read message header
            match timeout(
                timeout_config.network_read_timeout(),
                reader.read_exact(&mut buffer),
            )
            .await
            {
                Ok(Ok(_)) => {
                    let message_len =
                        u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

                    if message_len > timeout_config.max_message_size_bytes {
                        error!("Message too large: {message_len} bytes");
                        continue;
                    }

                    // Read message body
                    let mut message_buffer = vec![0u8; message_len];
                    match timeout(
                        timeout_config.network_read_timeout(),
                        reader.read_exact(&mut message_buffer),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {
                            match bincode::deserialize::<Response<R>>(&message_buffer) {
                                Ok(response) => {
                                    let request_id = response.request_id;

                                    // Find the pending request sender and calculate latency
                                    if let Some((_, (sender, start_time))) =
                                        pending_requests.remove(&request_id)
                                    {
                                        let latency = start_time.elapsed();
                                        let send_start = std::time::Instant::now();
                                        match tokio::time::timeout(
                                            std::time::Duration::from_secs(3),
                                            sender.send(response.response),
                                        )
                                        .await
                                        {
                                            Ok(Ok(())) => {
                                                let send_duration = send_start.elapsed();
                                                if send_duration
                                                    > std::time::Duration::from_millis(50)
                                                {
                                                    warn!("Slow response channel send for request {}: took {:?}",
                                                          request_id, send_duration);
                                                }
                                                metrics.record_successful_request(latency);
                                                request_rate_tracker.record_request();
                                            }
                                            Ok(Err(e)) => {
                                                error!(
                                                    "Failed to send response for request {}: {}",
                                                    request_id, e
                                                );
                                                metrics.record_failed_request();
                                            }
                                            Err(_) => {
                                                error!("Response channel send timeout for request {} after 3s - possible channel deadlock!", request_id);
                                                metrics.record_failed_request();
                                            }
                                        }
                                    } else {
                                        warn!(
                                            "Received response for unknown request {}",
                                            request_id
                                        );
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to deserialize response: {e}");
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            error!("Failed to read message body: {e}");
                            break;
                        }
                        Err(_) => {
                            error!("Timeout reading message body");
                            break;
                        }
                    }
                }
                Ok(Err(e)) => {
                    if e.kind() == ErrorKind::UnexpectedEof {
                        debug!("Client read task - connection closed by server");
                    } else {
                        error!("Client read task - failed to read message header: {e}");
                    }
                    break;
                }
                Err(e) => {
                    error!("Client read task - timeout reading message header: {e}");
                    break;
                }
            }
        }

        debug!("Client read task completed");
        Ok(())
    }

    async fn handle_write_task(
        mut writer: WriteHalf<VsockStream>,
        mut request_rx: mpsc::Receiver<RequestWithResponse<C, R>>,
        pending_requests: Arc<DashMap<u128, (mpsc::Sender<R>, Instant)>>,
        timeout_config: TimeoutConfig,
        metrics: Arc<MetricsTracker>,
        request_rate_tracker: Arc<RequestRateTracker>,
    ) -> Result<()> {
        while let Some((request, response_sender)) = request_rx.recv().await {
            let request_id = request.request_id;
            let start_time = Instant::now();

            // Store the response sender with timestamp for correlation
            pending_requests.insert(request_id, (response_sender, start_time));

            // Serialize and send the request
            match bincode::serialize(&request) {
                Ok(request_data) => {
                    if let Err(e) =
                        Self::send_message(&mut writer, &request_data, &timeout_config).await
                    {
                        error!("Failed to send request {}: {}", request_id, e);
                        // Remove from pending requests and notify sender of failure
                        if let Some((_, (sender, _start_time))) =
                            pending_requests.remove(&request_id)
                        {
                            error!(
                                "Failed to remove request from pending collection {}",
                                request_id
                            );
                            // Can't send generic error - just drop the sender
                            drop(sender);
                        }
                        metrics.record_failed_request();
                    } else {
                        request_rate_tracker.record_request();
                    }
                }
                Err(e) => {
                    error!("Failed to serialize request {}: {}", request_id, e);
                    // Remove from pending and notify failure
                    if let Some((_, (sender, _start_time))) = pending_requests.remove(&request_id) {
                        error!(
                            "Failed to remove request from pending collection {}",
                            request_id
                        );
                        // Can't send generic error - just drop the sender
                        drop(sender);
                    }
                    metrics.record_failed_request();
                }
            }
        }

        debug!("Client write task completed - request channel closed");
        Ok(())
    }

    async fn send_message(
        writer: &mut WriteHalf<VsockStream>,
        message_data: &[u8],
        timeout_config: &TimeoutConfig,
    ) -> Result<()> {
        let message_size = message_data.len();

        // Log message size for optimization tracking
        if message_size > 1024 * 1024 {
            // Log messages > 1MB
            warn!(
                "Large message being sent: {} bytes ({:.2} MB)",
                message_size,
                message_size as f64 / (1024.0 * 1024.0)
            );
        } else if message_size > 100 * 1024 {
            // Log messages > 100KB
            debug!(
                "Medium message being sent: {} bytes ({} KB)",
                message_size,
                message_size / 1024
            );
        }

        // Check message size before sending to prevent enclave rejection
        if message_size > timeout_config.max_message_size_bytes {
            return Err(anyhow!(
                "Message too large before sending: {} bytes (max {})",
                message_size,
                timeout_config.max_message_size_bytes
            ));
        }

        let length_bytes = (message_data.len() as u32).to_be_bytes();

        timeout(
            timeout_config.network_write_timeout(),
            writer.write_all(&length_bytes),
        )
        .await
        .map_err(|e| anyhow!("Timeout writing message length: {e}"))?
        .map_err(|e| anyhow!("Failed to write message length: {e}"))?;

        timeout(
            timeout_config.network_write_timeout(),
            writer.write_all(message_data),
        )
        .await
        .map_err(|e| anyhow!("Timeout writing message data: {e}"))?
        .map_err(|e| anyhow!("Failed to write message data: {e}"))?;

        Ok(())
    }

    pub fn get_metrics(&self) -> ConnectionMetrics {
        self.metrics.get_metrics()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request<C> {
    pub request_id: u128,
    pub command: C,
}

impl<C> From<C> for Request<C> {
    fn from(command: C) -> Self {
        Self {
            request_id: uuid::Uuid::now_v7().as_u128(),
            command,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response<R> {
    pub request_id: u128,
    pub response: R,
}

impl<R> Response<R> {
    pub fn from_with_id(request_id: u128, response: R) -> Self {
        Self {
            request_id,
            response,
        }
    }
}

pub trait ServerCommandHandler<C, R>: Send + Sync {
    fn handle_command(
        &self,
        command: C,
    ) -> Pin<Box<dyn Future<Output = Result<R, anyhow::Error>> + Send + '_>>;
}

pub struct MultiplexedConnectionHandler<C, R> {
    handler: ConnectionHandler<C, R>,
    active_connections: Arc<AtomicU32>,
    pub metrics: Arc<MetricsTracker>,
}

impl<C, R> MultiplexedConnectionHandler<C, R>
where
    C: Clone + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize + 'static,
    R: Clone + Send + Sync + serde::Serialize + for<'de> serde::Deserialize<'de> + 'static,
{
    pub fn new(
        handler: ConnectionHandler<C, R>,
        active_connections: Arc<AtomicU32>,
        metrics: Arc<MetricsTracker>,
    ) -> Self {
        Self {
            handler,
            active_connections,
            metrics,
        }
    }

    pub async fn handle(
        self,
        stream: VsockStream,
        request_rate_tracker: Arc<RequestRateTracker>,
        timeout_config: TimeoutConfig,
    ) -> Result<()> {
        self.active_connections.fetch_add(1, Ordering::AcqRel);
        info!("New multiplexed connection established");

        let result = self
            .handler
            .handle_connection(
                stream,
                self.active_connections.clone(),
                request_rate_tracker,
                timeout_config,
            )
            .await;

        self.active_connections.fetch_sub(1, Ordering::AcqRel);
        info!("Multiplexed connection closed");

        result
    }

    pub fn get_metrics(&self) -> ConnectionMetrics {
        self.metrics.get_metrics()
    }

    pub fn is_healthy(&self) -> bool {
        self.get_metrics().is_healthy()
    }
}

pub fn create_server_handler<C, R>(
    command_handler: Arc<dyn ServerCommandHandler<C, R>>,
    active_connections: Arc<AtomicU32>,
) -> MultiplexedConnectionHandler<C, R>
where
    C: Clone + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize + 'static,
    R: Clone + Send + Sync + serde::Serialize + for<'de> serde::Deserialize<'de> + 'static,
{
    let metrics = Arc::new(MetricsTracker::new());
    let server_handler = ServerHandler::new(command_handler, metrics.clone());
    let handler = ConnectionHandler::Server(server_handler);
    MultiplexedConnectionHandler::new(handler, active_connections, metrics)
}

pub fn create_client_handler<C, R>(
    active_connections: Arc<AtomicU32>,
    timeout_config: &TimeoutConfig,
) -> (MultiplexedConnectionHandler<C, R>, RequestSender<C, R>)
where
    C: Clone + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize + 'static,
    R: Clone + Send + Sync + serde::Serialize + for<'de> serde::Deserialize<'de> + 'static,
{
    let metrics = Arc::new(MetricsTracker::new());
    let (client_handler, request_tx) =
        ClientHandler::new(metrics.clone(), timeout_config.max_channel_size);
    let handler = ConnectionHandler::Client(client_handler);
    let connection_handler =
        MultiplexedConnectionHandler::new(handler, active_connections, metrics);

    (connection_handler, request_tx)
}

pub struct Client<C, R> {
    request_tx: RequestSender<C, R>,
    timeout_config: TimeoutConfig,
    metrics: Arc<MetricsTracker>,
}

impl<C, R> Client<C, R>
where
    C: Clone + Send + Sync,
    R: Clone + Send + Sync,
{
    pub fn new(
        request_tx: RequestSender<C, R>,
        timeout_config: TimeoutConfig,
        metrics: Arc<MetricsTracker>,
    ) -> Self {
        Self {
            request_tx,
            timeout_config,
            metrics,
        }
    }

    pub async fn send_request(&self, request: Request<C>) -> Result<R> {
        let (response_tx, mut response_rx) = mpsc::channel(self.timeout_config.max_channel_size);

        debug!(
            "Created response channel with capacity {} for request {}",
            self.timeout_config.max_channel_size, request.request_id
        );

        let send_start = std::time::Instant::now();
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.request_tx.send((request.clone(), response_tx)),
        )
        .await
        {
            Ok(Ok(())) => {
                let send_duration = send_start.elapsed();
                if send_duration > std::time::Duration::from_millis(500) {
                    warn!(
                        "Slow request channel send for {}: took {:?} (possible channel congestion)",
                        request.request_id, send_duration
                    );
                }
            }
            Ok(Err(e)) => {
                return Err(anyhow!(
                    "Connection closed - unable to send request {}: {}",
                    request.request_id,
                    e
                ));
            }
            Err(_) => {
                return Err(anyhow!(
                    "Request channel send timeout for {} after 10s - channel deadlock detected!",
                    request.request_id
                ));
            }
        }

        debug!("Request {} queued for sending", request.request_id);

        let timeout_duration = self.timeout_config.vsock_timeout();
        tokio::time::timeout(timeout_duration, response_rx.recv())
            .await
            .map_err(|e| {
                anyhow!(
                    "Request {} timed out after {:?} {}",
                    request.request_id,
                    timeout_duration,
                    e
                )
            })?
            .ok_or(anyhow!(
                "Response channel closed for request {}",
                request.request_id
            ))
    }

    pub fn is_connected(&self) -> bool {
        !self.request_tx.is_closed()
    }

    pub fn get_metrics(&self) -> ConnectionMetrics {
        self.metrics.get_metrics()
    }

    pub fn is_healthy(&self) -> bool {
        self.is_connected() && self.get_metrics().is_healthy()
    }

    pub fn connection_state(&self) -> ConnectionState {
        if !self.is_connected() {
            ConnectionState::Failed
        } else if self.get_metrics().requests_in_current_window > 0 {
            ConnectionState::Active
        } else {
            ConnectionState::Idle
        }
    }

    pub fn create_request(&self, command: C) -> Request<C> {
        Request {
            request_id: Uuid::now_v7().as_u128(),
            command,
        }
    }
}

pub fn create_client_with_wrapper<C, R>(
    active_connections: Arc<AtomicU32>,
    timeout_config: &TimeoutConfig,
) -> (MultiplexedConnectionHandler<C, R>, Client<C, R>)
where
    C: Clone + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize + 'static,
    R: Clone + Send + Sync + serde::Serialize + for<'de> serde::Deserialize<'de> + 'static,
{
    let (connection_handler, request_tx) =
        create_client_handler(active_connections, timeout_config);

    let metrics = connection_handler.metrics.clone();
    let client = Client::new(request_tx, timeout_config.clone(), metrics);
    (connection_handler, client)
}

impl<C, R> MultiplexedConnectionHandler<C, R>
where
    C: Clone + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize + 'static,
    R: Clone + Send + Sync + serde::Serialize + for<'de> serde::Deserialize<'de> + 'static,
{
    pub fn connection_state(&self) -> ConnectionState {
        let metrics = self.get_metrics();
        if metrics.requests_in_current_window > 0 {
            ConnectionState::Active
        } else if metrics.failure_rate > 75.0 {
            ConnectionState::Failed
        } else {
            ConnectionState::Idle
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub state: ConnectionState,
    pub metrics: ConnectionMetrics,
    pub active_connections: u32,
}

impl<C, R> MultiplexedConnectionHandler<C, R>
where
    C: Clone + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize + 'static,
    R: Clone + Send + Sync + serde::Serialize + for<'de> serde::Deserialize<'de> + 'static,
{
    pub fn get_stats(&self) -> ConnectionStats {
        ConnectionStats {
            state: self.connection_state(),
            metrics: self.get_metrics(),
            active_connections: self.active_connections.load(Ordering::Acquire),
        }
    }
}
