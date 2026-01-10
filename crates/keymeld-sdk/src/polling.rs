use crate::config::PollingConfig;
use crate::error::SdkError;
use std::future::Future;

pub(crate) enum PollResult<T> {
    Ready(T),
    Pending,
}

pub(crate) async fn poll_until<T, F, Fut>(
    config: &PollingConfig,
    mut poll_fn: F,
) -> Result<T, SdkError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<PollResult<T>, SdkError>>,
{
    let mut delay = config.initial_delay;

    for attempt in 1..=config.max_attempts {
        match poll_fn().await? {
            PollResult::Ready(result) => return Ok(result),
            PollResult::Pending => {
                if attempt >= config.max_attempts {
                    break;
                }

                let jitter_range = (delay.as_millis() as f64 * config.jitter) as u64;
                let jitter = if jitter_range > 0 {
                    random_u64() % jitter_range
                } else {
                    0
                };
                let sleep_duration = delay + std::time::Duration::from_millis(jitter);

                sleep(sleep_duration).await;

                let next_delay_ms = (delay.as_millis() as f64 * config.backoff_multiplier) as u64;
                delay = std::time::Duration::from_millis(next_delay_ms).min(config.max_delay);
            }
        }
    }

    Err(SdkError::Internal(format!(
        "Polling timed out after {} attempts",
        config.max_attempts
    )))
}

#[cfg(not(target_arch = "wasm32"))]
async fn sleep(duration: std::time::Duration) {
    tokio::time::sleep(duration).await;
}

#[cfg(target_arch = "wasm32")]
async fn sleep(duration: std::time::Duration) {
    gloo_timers::future::TimeoutFuture::new(duration.as_millis() as u32).await;
}

#[cfg(not(target_arch = "wasm32"))]
fn random_u64() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish()
}

#[cfg(target_arch = "wasm32")]
fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    // getrandom uses crypto.getRandomValues() in browser which should never fail
    if getrandom::getrandom(&mut bytes).is_err() {
        return 0; // Fall back to no jitter if random fails
    }
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn test_poll_immediate_success() {
        let config = PollingConfig {
            max_attempts: 10,
            initial_delay: std::time::Duration::from_millis(10),
            max_delay: std::time::Duration::from_millis(100),
            backoff_multiplier: 1.5,
            jitter: 0.0,
        };

        let result = poll_until(&config, || async { Ok(PollResult::Ready(42)) }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_poll_eventual_success() {
        let config = PollingConfig {
            max_attempts: 10,
            initial_delay: std::time::Duration::from_millis(10),
            max_delay: std::time::Duration::from_millis(100),
            backoff_multiplier: 1.5,
            jitter: 0.0,
        };

        let counter = AtomicU32::new(0);

        let result = poll_until(&config, || {
            let count = counter.fetch_add(1, Ordering::SeqCst);
            async move {
                if count >= 3 {
                    Ok(PollResult::Ready("success"))
                } else {
                    Ok(PollResult::Pending)
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), "success");
        assert!(counter.load(Ordering::SeqCst) >= 4);
    }

    #[tokio::test]
    async fn test_poll_timeout() {
        let config = PollingConfig {
            max_attempts: 3,
            initial_delay: std::time::Duration::from_millis(10),
            max_delay: std::time::Duration::from_millis(100),
            backoff_multiplier: 1.5,
            jitter: 0.0,
        };

        let result: Result<(), SdkError> =
            poll_until(&config, || async { Ok(PollResult::Pending) }).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }
}
