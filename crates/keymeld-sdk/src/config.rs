use std::time::Duration;

#[derive(Debug, Clone)]
pub struct PollingConfig {
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
    pub jitter: f64,
}

impl Default for PollingConfig {
    fn default() -> Self {
        Self {
            max_attempts: 120,
            initial_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(5),
            backoff_multiplier: 1.5,
            jitter: 0.25,
        }
    }
}

impl PollingConfig {
    pub fn fast() -> Self {
        Self {
            max_attempts: 60,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(2),
            backoff_multiplier: 1.3,
            jitter: 0.1,
        }
    }

    pub fn patient() -> Self {
        Self {
            max_attempts: 240,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 1.5,
            jitter: 0.3,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub compression_threshold: usize,
    pub timeout: Duration,
    pub debug_logging: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            compression_threshold: 256,
            timeout: Duration::from_secs(30),
            debug_logging: false,
        }
    }
}
