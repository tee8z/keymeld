use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    pub vsock_timeout_secs: u64,
    pub nonce_generation_timeout_secs: u64,
    pub session_init_timeout_secs: u64,
    pub signing_timeout_secs: u64,
    pub network_write_timeout_secs: u64,
    pub network_read_timeout_secs: u64,
    pub connection_retry_delay_ms: u64,
    pub max_message_size_bytes: usize,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            vsock_timeout_secs: 300, // 5 minutes for crypto operations (increased for AddParticipant with large encrypted data)
            nonce_generation_timeout_secs: 180, // 3 minutes
            session_init_timeout_secs: 1800, // 30 minutes
            signing_timeout_secs: 600, // 10 minutes
            network_write_timeout_secs: 5, // 5 seconds for individual network writes
            network_read_timeout_secs: 300, // 5 minutes for reading crypto operation responses
            connection_retry_delay_ms: 100, // 100ms delay between connection retries
            max_message_size_bytes: 1024 * 1024, // 1MB maximum message size
        }
    }
}

impl TimeoutConfig {
    pub fn vsock_timeout(&self) -> Duration {
        Duration::from_secs(self.vsock_timeout_secs)
    }

    pub fn nonce_generation_timeout(&self) -> Duration {
        Duration::from_secs(self.nonce_generation_timeout_secs)
    }

    pub fn session_init_timeout(&self) -> Duration {
        Duration::from_secs(self.session_init_timeout_secs)
    }

    pub fn signing_timeout(&self) -> Duration {
        Duration::from_secs(self.signing_timeout_secs)
    }

    pub fn network_write_timeout(&self) -> Duration {
        Duration::from_secs(self.network_write_timeout_secs)
    }

    pub fn network_read_timeout(&self) -> Duration {
        Duration::from_secs(self.network_read_timeout_secs)
    }

    pub fn connection_retry_delay(&self) -> Duration {
        Duration::from_millis(self.connection_retry_delay_ms)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.vsock_timeout_secs == 0 {
            return Err("VSock timeout must be greater than 0".to_string());
        }
        if self.nonce_generation_timeout_secs == 0 {
            return Err("Nonce generation timeout must be greater than 0".to_string());
        }
        if self.session_init_timeout_secs == 0 {
            return Err("Session init timeout must be greater than 0".to_string());
        }
        if self.signing_timeout_secs == 0 {
            return Err("Signing timeout must be greater than 0".to_string());
        }
        if self.network_write_timeout_secs == 0 {
            return Err("Network write timeout must be greater than 0".to_string());
        }
        if self.network_read_timeout_secs == 0 {
            return Err("Network read timeout must be greater than 0".to_string());
        }
        if self.max_message_size_bytes == 0 {
            return Err("Max message size must be greater than 0".to_string());
        }
        if self.connection_retry_delay_ms == 0 {
            return Err("Connection retry delay must be greater than 0".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial delay between retries (milliseconds)
    pub initial_delay_ms: u64,
    /// Maximum delay between retries (milliseconds)
    pub max_delay_ms: u64,
    /// Multiplier for exponential backoff
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 300,
            max_delay_ms: 5000,
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryConfig {
    pub fn initial_delay(&self) -> Duration {
        Duration::from_millis(self.initial_delay_ms)
    }

    pub fn max_delay(&self) -> Duration {
        Duration::from_millis(self.max_delay_ms)
    }

    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return self.initial_delay();
        }

        let delay_ms =
            (self.initial_delay_ms as f64 * self.backoff_multiplier.powi(attempt as i32)) as u64;

        Duration::from_millis(delay_ms.min(self.max_delay_ms))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.max_attempts == 0 {
            return Err("Max attempts must be greater than 0".to_string());
        }
        if self.initial_delay_ms == 0 {
            return Err("Initial delay must be greater than 0".to_string());
        }
        if self.max_delay_ms < self.initial_delay_ms {
            return Err("Max delay must be greater than or equal to initial delay".to_string());
        }
        if self.backoff_multiplier <= 1.0 {
            return Err("Backoff multiplier must be greater than 1.0".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayLimits {
    /// Default maximum number of signing sessions per keygen session
    pub default_max_signing_sessions: u32,
    /// Maximum request body size in bytes
    pub max_request_size_bytes: usize,
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
}

impl Default for GatewayLimits {
    fn default() -> Self {
        Self {
            default_max_signing_sessions: 100,
            max_request_size_bytes: 1024 * 1024, // 1MB
            request_timeout_secs: 120,           // 2 minutes for crypto operations
        }
    }
}

impl GatewayLimits {
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.default_max_signing_sessions == 0 {
            return Err("Default max signing sessions must be greater than 0".to_string());
        }
        if self.max_request_size_bytes == 0 {
            return Err("Max request size must be greater than 0".to_string());
        }
        if self.request_timeout_secs == 0 {
            return Err("Request timeout must be greater than 0".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_config_defaults() {
        let config = TimeoutConfig::default();
        assert_eq!(config.vsock_timeout_secs, 300);
        assert_eq!(config.nonce_generation_timeout_secs, 180);
        assert_eq!(config.session_init_timeout_secs, 1800);
        assert_eq!(config.network_write_timeout_secs, 5);
        assert_eq!(config.network_read_timeout_secs, 300);
        assert_eq!(config.connection_retry_delay_ms, 100);
        assert_eq!(config.max_message_size_bytes, 1024 * 1024);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_timeout_config_validation() {
        let config = TimeoutConfig {
            vsock_timeout_secs: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = TimeoutConfig {
            network_write_timeout_secs: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = TimeoutConfig {
            max_message_size_bytes: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = TimeoutConfig {
            connection_retry_delay_ms: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_timeout_config_duration_conversions() {
        let config = TimeoutConfig::default();
        assert_eq!(config.vsock_timeout(), Duration::from_secs(300));
        assert_eq!(config.nonce_generation_timeout(), Duration::from_secs(180));
        assert_eq!(config.session_init_timeout(), Duration::from_secs(1800));
        assert_eq!(config.signing_timeout(), Duration::from_secs(600));
        assert_eq!(config.network_write_timeout(), Duration::from_secs(5));
        assert_eq!(config.network_read_timeout(), Duration::from_secs(300));
        assert_eq!(config.connection_retry_delay(), Duration::from_millis(100));
    }

    #[test]
    fn test_retry_config_defaults() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.initial_delay_ms, 300);
        assert_eq!(config.backoff_multiplier, 2.0);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_retry_config_exponential_backoff() {
        let config = RetryConfig::default();
        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(300));
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(600));
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(1200));
    }

    #[test]
    fn test_retry_config_max_delay_cap() {
        let config = RetryConfig {
            max_attempts: 10,
            initial_delay_ms: 1000,
            max_delay_ms: 5000,
            backoff_multiplier: 2.0,
        };

        let high_attempt_delay = config.delay_for_attempt(10);
        assert_eq!(high_attempt_delay, Duration::from_millis(5000));
    }

    #[test]
    fn test_gateway_limits_defaults() {
        let limits = GatewayLimits::default();
        assert_eq!(limits.default_max_signing_sessions, 100);
        assert_eq!(limits.max_request_size_bytes, 1024 * 1024);
        assert!(limits.validate().is_ok());
    }
}
