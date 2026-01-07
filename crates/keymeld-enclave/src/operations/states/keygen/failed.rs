use keymeld_core::SessionId;
use std::time::SystemTime;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct Failed {
    pub session_id: SessionId,
    pub error: String,
    pub created_at: SystemTime,
}

impl Failed {
    pub fn new(session_id: SessionId, created_at: SystemTime, error: String) -> Self {
        let duration = SystemTime::now()
            .duration_since(created_at)
            .unwrap_or_default();

        warn!(
            "Keygen session {} failed after {:.2}s with error: {}",
            session_id,
            duration.as_secs_f64(),
            error
        );

        Self {
            session_id,
            error,
            created_at,
        }
    }
}
