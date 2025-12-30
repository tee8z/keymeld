use keymeld_core::SessionId;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct Failed {
    pub session_id: SessionId,
    pub error: String,
    pub created_at: SystemTime,
    pub failed_at: Duration,
}

impl Failed {
    pub fn new(session_id: SessionId, error: String, created_at: SystemTime) -> Self {
        Self {
            session_id,
            error,
            created_at,
            failed_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default(),
        }
    }
}
