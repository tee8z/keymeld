use crate::operations::{context_aware_session::ContextAwareSession, SessionContext};
use dashmap::DashMap;
use keymeld_core::{
    protocol::{Command, EnclaveError, SessionError},
    SessionId,
};
use std::sync::{Arc, RwLock};
use std::{collections::BTreeMap, time::Duration};
use tokio::{
    sync::{mpsc, oneshot},
    time::sleep,
};
use tracing::{debug, error, info};

pub struct Task {
    pub command: Command,
    pub response_tx: oneshot::Sender<Result<(), EnclaveError>>,
}

pub struct Queue {
    /// Map of session ID to session task handle
    session_tasks: Arc<RwLock<BTreeMap<SessionId, Handle>>>,
    /// Sessions from operator
    sessions: Arc<DashMap<SessionId, ContextAwareSession>>,
}

#[derive(Debug)]
pub struct Handle {
    /// Channel to send commands to the session task
    command_tx: mpsc::UnboundedSender<Task>,
    /// Task handle for cleanup
    task_handle: tokio::task::JoinHandle<()>,
}

impl Queue {
    /// Create a new queue
    pub fn new(sessions: Arc<DashMap<SessionId, ContextAwareSession>>) -> Self {
        Self {
            session_tasks: Arc::new(RwLock::new(BTreeMap::new())),
            sessions,
        }
    }

    /// Process a command for a specific session
    pub async fn process_command(
        &self,
        session_id: SessionId,
        command: Command,
    ) -> Result<(), EnclaveError> {
        let command_tx = self.get_or_create_session_task(session_id.clone()).await?;

        let (response_tx, response_rx) = oneshot::channel();
        let task = Task {
            command,
            response_tx,
        };

        command_tx.send(task).map_err(|_| {
            EnclaveError::Session(SessionError::ProcessingFailed(
                "Session task channel closed".to_string(),
            ))
        })?;

        response_rx.await.map_err(|_| {
            EnclaveError::Session(SessionError::ProcessingFailed(
                "Failed to receive response from session task".to_string(),
            ))
        })?
    }

    async fn get_or_create_session_task(
        &self,
        session_id: SessionId,
    ) -> Result<mpsc::UnboundedSender<Task>, EnclaveError> {
        {
            let tasks = self.session_tasks.read().unwrap();
            if let Some(handle) = tasks.get(&session_id) {
                if !handle.task_handle.is_finished() {
                    return Ok(handle.command_tx.clone());
                }
            }
        }

        self.create_session_task(session_id).await
    }

    async fn create_session_task(
        &self,
        session_id: SessionId,
    ) -> Result<mpsc::UnboundedSender<Task>, EnclaveError> {
        // Verify session exists
        if !self.sessions.contains_key(&session_id) {
            return Err(EnclaveError::Session(SessionError::NotFound(session_id)));
        }

        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let sessions = self.sessions.clone();
        let session_id_clone = session_id.clone();

        let task_handle = tokio::spawn(async move {
            let mut command_rx: mpsc::UnboundedReceiver<Task> = command_rx;
            info!("Session task started for session {}", session_id_clone);

            while let Some(task) = command_rx.recv().await {
                debug!(
                    "Session {} processing command: {}",
                    session_id_clone, task.command.command
                );

                let result =
                    Self::process_session_command(&sessions, &session_id_clone, task.command).await;

                if let Err(e) = &result {
                    error!(
                        "Session {} failed to process command: {}",
                        session_id_clone, e
                    );
                }

                // Send response back (ignore if receiver dropped)
                let _ = task.response_tx.send(result);
            }

            info!("Session task ended for session {}", session_id_clone);
        });

        let handle = Handle {
            command_tx: command_tx.clone(),
            task_handle,
        };

        // Store the handle
        {
            let mut tasks = self.session_tasks.write().unwrap();
            tasks.insert(session_id, handle);
        }

        // Return just the sender for the caller
        Ok(command_tx)
    }

    /// Process a command for a session - this is where the actual state machine processing happens
    /// Each session owns its context and processes commands independently
    async fn process_session_command(
        sessions: &DashMap<SessionId, ContextAwareSession>,
        session_id: &SessionId,
        command: Command,
    ) -> Result<(), EnclaveError> {
        debug!(
            "Processing command for session {}: {}",
            session_id, command.command
        );

        let mut processing_result: Option<Result<(), EnclaveError>> = None;

        // Use alter() for atomic state processing with owned context
        sessions.alter(session_id, |_key, mut current_session| {
            debug!(
                "Session {} current state: {}, processing command",
                current_session.session_id(),
                current_session
            );

            // Check command idempotency using the proper MuSig rules
            // - Once-only commands: Check kind() (don't process same command type twice per session)
            // - Repeatable commands: Check command_id (don't process exact same command twice)
            let command_history = match &current_session.session_context {
                SessionContext::Keygen(ctx) => &ctx.command_history,
                SessionContext::Signing(ctx) => &ctx.command_history,
            };

            match current_session
                .session_context
                .check_command_idempotency(&command.command)
            {
                Ok(true) => {
                    debug!(
                        "Command kind {} already processed for session {} - skipping",
                        command.command, session_id
                    );
                    processing_result = Some(Ok(()));
                    return current_session;
                }
                Ok(false) => {
                    for processed_cmd in command_history {
                        if processed_cmd.command_id == command.command_id {
                            debug!(
                                "Command {} already processed for session {} - skipping",
                                command.command_id, session_id
                            );
                            processing_result = Some(Ok(()));
                            return current_session;
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to check command idempotency for session {}: {}",
                        session_id, e
                    );
                    processing_result = Some(Err(e));
                    return current_session;
                }
            }

            // Process the inner EnclaveCommand using the session's owned context
            match current_session.process(&command.command) {
                Ok(()) => {
                    debug!(
                        "Processed session {}, new state: {}",
                        current_session.session_id(),
                        current_session
                    );

                    current_session
                        .session_context
                        .add_processed_command(command.clone());

                    if let Err(e) = current_session.check_for_failure() {
                        info!(
                            "Session {} is in failed state, storing it anyway",
                            current_session.session_id()
                        );
                        processing_result = Some(Err(e));
                    } else {
                        processing_result = Some(Ok(()));
                    }

                    current_session
                }
                Err(e) => {
                    error!(
                        "Failed to process command for session {}: {}",
                        current_session.session_id(),
                        e
                    );

                    let failed_session = current_session.create_failed_from_error(e.clone());
                    processing_result = Some(Err(e));
                    failed_session
                }
            }
        });

        processing_result.unwrap_or_else(|| {
            Err(EnclaveError::Session(SessionError::NotFound(
                session_id.clone(),
            )))
        })
    }

    pub fn cleanup_finished_tasks(&self) {
        let mut to_remove = Vec::new();

        {
            let tasks = self.session_tasks.read().unwrap();
            for (session_id, handle) in tasks.iter() {
                if handle.task_handle.is_finished() {
                    to_remove.push(session_id.clone());
                }
            }
        }

        if !to_remove.is_empty() {
            let mut tasks = self.session_tasks.write().unwrap();
            for session_id in to_remove {
                debug!("Cleaning up finished task for session {}", session_id);
                tasks.remove(&session_id);
            }
        }
    }

    pub fn active_task_count(&self) -> usize {
        self.session_tasks.read().unwrap().len()
    }

    pub fn has_active_task(&self, session_id: &SessionId) -> bool {
        let tasks = self.session_tasks.read().unwrap();
        if let Some(handle) = tasks.get(session_id) {
            !handle.task_handle.is_finished()
        } else {
            false
        }
    }

    pub async fn shutdown(&self) {
        let task_count = self.active_task_count();
        info!("Shutting down queue with {} active tasks", task_count);

        if task_count > 0 {
            info!("Waiting for {} session tasks to finish", task_count);
            sleep(Duration::from_secs(1)).await;
        }

        // Clear all tasks
        {
            let mut tasks = self.session_tasks.write().unwrap();
            tasks.clear();
        }

        info!("Queue shutdown complete");
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        // Abort all remaining tasks
        let tasks = self.session_tasks.read().unwrap();
        for (_session_id, handle) in tasks.iter() {
            handle.task_handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use keymeld_core::protocol::{EnclaveCommand, KeygenCommand, MusigCommand};

    use crate::operations::{
        context::EnclaveSharedContext,
        session_context::SessionContext,
        states::{KeygenStatus, OperatorStatus},
        KeygenInitialized,
    };
    use std::sync::Arc;

    use super::*;

    fn init_test() {
        let _ = tracing::subscriber::set_default(tracing::subscriber::NoSubscriber::default());
    }

    #[tokio::test]
    async fn test_queue_creation() {
        let sessions = Arc::new(DashMap::new());
        let queue = Queue::new(sessions);
        assert_eq!(queue.active_task_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_session_task_lifecycle() {
        init_test();
        let sessions = Arc::new(DashMap::new());
        let session_id = SessionId::new_v7();

        // Create test enclave context
        let enclave_context = Arc::new(std::sync::RwLock::new(EnclaveSharedContext::new(
            keymeld_core::identifiers::EnclaveId::new(1),
            vec![1, 2, 3],
            vec![4, 5, 6],
            None,
            keymeld_core::managed_vsock::config::TimeoutConfig::default(),
        )));

        // Create test session context
        let session_context = SessionContext::new_keygen(session_id.clone());

        // Create context-aware session
        let context_aware_session = ContextAwareSession::new(
            OperatorStatus::Keygen(KeygenStatus::Initialized(KeygenInitialized::new(
                session_id.clone(),
            ))),
            session_context,
            enclave_context,
        );

        // Add the context-aware session
        sessions.insert(session_id.clone(), context_aware_session);

        let queue = Queue::new(sessions);

        // Initially no tasks
        assert_eq!(queue.active_task_count(), 0);
        assert!(!queue.has_active_task(&session_id));

        // This should create a task and process it with a valid session-level command
        // Use InitKeygenSession which is valid for Initialized state
        let init_cmd = keymeld_core::protocol::InitKeygenSessionCommand {
            keygen_session_id: session_id.clone(),
            coordinator_user_id: None,
            coordinator_encrypted_private_key: None,
            encrypted_session_secret: None,
            timeout_secs: 300,
            enclave_public_keys: vec![],
            expected_participant_count: 2,
            expected_participants: vec![],
            encrypted_taproot_tweak: String::new(),
        };
        let _result = queue
            .process_command(
                session_id.clone(),
                Command::new(EnclaveCommand::Musig(MusigCommand::Keygen(
                    KeygenCommand::InitSession(init_cmd),
                ))),
            )
            .await;

        // After process_command returns, the task has been created and is now waiting for more commands
        // The task handle remains alive in the queue
        assert_eq!(queue.active_task_count(), 1);
        assert!(queue.has_active_task(&session_id));
    }

    #[tokio::test]
    async fn test_cleanup_finished_tasks() {
        let sessions = Arc::new(DashMap::new());
        let queue = Queue::new(sessions);

        // Initially no tasks
        assert_eq!(queue.active_task_count(), 0);

        // Cleanup should not panic on empty queue
        queue.cleanup_finished_tasks();
        assert_eq!(queue.active_task_count(), 0);
    }

    #[tokio::test]
    async fn test_dashmap_btreemap_integration() {
        let sessions = Arc::new(DashMap::new());
        let session_id = SessionId::new_v7();

        // Create shared enclave context
        let enclave_context = Arc::new(std::sync::RwLock::new(EnclaveSharedContext::new(
            keymeld_core::identifiers::EnclaveId::new(1),
            vec![1, 2, 3],
            vec![4, 5, 6],
            None,
            keymeld_core::managed_vsock::config::TimeoutConfig::default(),
        )));

        // Add session to DashMap (simulates operator adding session)
        let session_context_1 = SessionContext::new_keygen(session_id.clone());
        let context_aware_session_1 = ContextAwareSession::new(
            OperatorStatus::Keygen(KeygenStatus::Initialized(KeygenInitialized::new(
                session_id.clone(),
            ))),
            session_context_1,
            enclave_context.clone(),
        );
        sessions.insert(session_id.clone(), context_aware_session_1);

        // Verify concurrent access to different sessions works
        let session_id_2 = SessionId::new_v7();
        let session_context_2 = SessionContext::new_keygen(session_id_2.clone());
        let context_aware_session_2 = ContextAwareSession::new(
            OperatorStatus::Keygen(KeygenStatus::Initialized(KeygenInitialized::new(
                session_id_2.clone(),
            ))),
            session_context_2,
            enclave_context.clone(),
        );
        sessions.insert(session_id_2.clone(), context_aware_session_2);

        let queue = Queue::new(sessions.clone());

        // Both sessions should be accessible
        assert!(sessions.contains_key(&session_id));
        assert!(sessions.contains_key(&session_id_2));
        assert_eq!(sessions.len(), 2);

        // Task management should use BTreeMap internally
        assert_eq!(queue.active_task_count(), 0);
        assert!(!queue.has_active_task(&session_id));
    }
}
