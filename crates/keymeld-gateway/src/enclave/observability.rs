//! Operator observations of the existing public enclave health protocol.
use std::sync::OnceLock;

#[derive(Clone, Debug)]
pub struct PublicObservation {
    pub observed_at: i64,
    pub uptime_seconds: u64,
    pub active_sessions: u32,
    pub key_epoch: u64,
}

/// Deployment labels are operator declarations, not attestation evidence.
pub fn deployment() -> Option<&'static (String, String)> {
    static VALUE: OnceLock<Option<(String, String)>> = OnceLock::new();
    VALUE
        .get_or_init(|| {
            let component = std::env::var("KEYMELD_ENCLAVE_COMPONENT").ok()?;
            let release = std::env::var("KEYMELD_ENCLAVE_RELEASE").ok()?;
            if [&component, &release].iter().all(|s| {
                !s.is_empty()
                    && s.len() <= 64
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            }) {
                Some((component, release))
            } else {
                None
            }
        })
        .as_ref()
}
