use crate::config::RateLimitConfig;
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderName, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub(crate) struct AdmissionLimiter {
    config: RateLimitConfig,
    client_ip_header: Option<HeaderName>,
    buckets: Mutex<Buckets>,
}

struct Buckets {
    global: Bucket,
    clients: HashMap<IpAddr, Bucket>,
    next_cleanup: Instant,
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl Bucket {
    fn new(burst: u32, now: Instant) -> Self {
        Self {
            tokens: f64::from(burst),
            updated: now,
        }
    }

    fn available(&self, burst: u32, rate: u32, now: Instant) -> f64 {
        (self.tokens + now.duration_since(self.updated).as_secs_f64() * f64::from(rate))
            .min(f64::from(burst))
    }

    fn refill(&mut self, burst: u32, rate: u32, now: Instant) -> Duration {
        self.tokens = self.available(burst, rate, now);
        self.updated = now;
        Duration::from_secs_f64(((1.0 - self.tokens) / f64::from(rate)).max(0.0))
    }
}

impl AdmissionLimiter {
    pub(crate) fn new(config: &RateLimitConfig) -> anyhow::Result<Arc<Self>> {
        config.validate()?;
        let now = Instant::now();
        Ok(Arc::new(Self {
            config: config.clone(),
            client_ip_header: config
                .client_ip_header
                .as_ref()
                .map(|name| HeaderName::from_bytes(name.as_bytes()))
                .transpose()?,
            buckets: Mutex::new(Buckets {
                global: Bucket::new(config.global_burst, now),
                clients: HashMap::new(),
                next_cleanup: now,
            }),
        }))
    }

    fn client_ip(&self, request: &Request) -> Result<IpAddr, StatusCode> {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
            .0
            .ip()
            .to_canonical();
        if self
            .config
            .trusted_proxy_ips
            .iter()
            .any(|ip| ip.to_canonical() == peer)
        {
            if let Some(header) = &self.client_ip_header {
                // Trust one overwritten address only. Forwarded chains and duplicate
                // headers are ambiguous, even when the immediate peer is trusted.
                let mut values = request.headers().get_all(header).iter();
                let value = values.next().ok_or(StatusCode::BAD_REQUEST)?;
                if values.next().is_some() {
                    return Err(StatusCode::BAD_REQUEST);
                }
                return value
                    .to_str()
                    .ok()
                    .and_then(|value| value.parse::<IpAddr>().ok())
                    .map(|ip| ip.to_canonical())
                    .ok_or(StatusCode::BAD_REQUEST);
            }
        }
        Ok(peer)
    }

    fn admit(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        // Never hold this lock while reading a body or awaiting enclave work.
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // Concurrent requests can acquire this lock in a different order from
        // their timestamps. Never move a bucket's refill clock backwards.
        let now = now.max(buckets.global.updated);
        let global_wait = buckets.global.refill(
            self.config.global_burst,
            self.config.global_requests_per_second,
            now,
        );
        if !global_wait.is_zero() {
            return Err(global_wait);
        }

        if now >= buckets.next_cleanup {
            // A fully replenished bucket can be removed without granting extra
            // capacity. Cleanup is throttled so fresh identities cannot force
            // an O(max_tracked_ips) scan on every rejected request.
            buckets.clients.retain(|_, bucket| {
                bucket.available(
                    self.config.per_ip_burst,
                    self.config.per_ip_requests_per_second,
                    now,
                ) < f64::from(self.config.per_ip_burst)
            });
            buckets.next_cleanup = now + Duration::from_secs(1);
        }

        if !buckets.clients.contains_key(&ip)
            && buckets.clients.len() >= self.config.max_tracked_ips
        {
            // Do not evict depleted buckets: rotating addresses must not reset
            // an existing client's budget or grow gateway memory without bound.
            return Err(Duration::from_secs(1));
        }
        let client = buckets
            .clients
            .entry(ip)
            .or_insert_with(|| Bucket::new(self.config.per_ip_burst, now));
        let client_wait = client.refill(
            self.config.per_ip_burst,
            self.config.per_ip_requests_per_second,
            now,
        );
        if !client_wait.is_zero() {
            return Err(client_wait);
        }
        client.tokens -= 1.0;
        buckets.global.tokens -= 1.0;
        Ok(())
    }
}

pub(crate) async fn limit_admission(
    State(limiter): State<Arc<AdmissionLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    // Polling stays available while creation, registration, approvals, key
    // changes, signing and fresh enclave attestation share admission budgets.
    let attestation_request = request.uri().path().ends_with("/public-key");
    if matches!(request.method(), &Method::GET | &Method::HEAD) && !attestation_request
        || request.method() == Method::OPTIONS
    {
        return next.run(request).await;
    }
    let ip = match limiter.client_ip(&request) {
        Ok(ip) => ip,
        Err(status) => return status.into_response(),
    };
    if let Err(wait) = limiter.admit(ip, Instant::now()) {
        let retry_after = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry_after.max(1).to_string())],
            Json(serde_json::json!({
                "error_code": "rate_limited",
                "message": "Gateway admission capacity exceeded; retry after the indicated delay"
            })),
        )
            .into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_budget_cannot_be_bypassed_by_rotating_peers() {
        let limiter = AdmissionLimiter::new(&RateLimitConfig {
            global_burst: 2,
            global_requests_per_second: 1,
            ..Default::default()
        })
        .unwrap();
        let now = Instant::now();
        assert!(limiter.admit("192.0.2.1".parse().unwrap(), now).is_ok());
        assert!(limiter.admit("192.0.2.2".parse().unwrap(), now).is_ok());
        assert!(limiter.admit("192.0.2.3".parse().unwrap(), now).is_err());
        assert!(limiter
            .admit("192.0.2.3".parse().unwrap(), now + Duration::from_secs(1))
            .is_ok());
    }

    #[test]
    fn peer_storage_is_bounded_without_resetting_exhausted_budgets() {
        let limiter = AdmissionLimiter::new(&RateLimitConfig {
            per_ip_burst: 1,
            per_ip_requests_per_second: 1,
            max_tracked_ips: 1,
            ..Default::default()
        })
        .unwrap();
        let now = Instant::now();
        let first = "192.0.2.1".parse().unwrap();
        let second = "192.0.2.2".parse().unwrap();
        assert!(limiter.admit(first, now).is_ok());
        assert!(limiter.admit(second, now).is_err());
        assert!(limiter.admit(first, now).is_err());
        assert_eq!(limiter.buckets.lock().unwrap().clients.len(), 1);
        assert!(limiter.admit(second, now + Duration::from_secs(1)).is_ok());
        assert_eq!(limiter.buckets.lock().unwrap().clients.len(), 1);
    }
}
