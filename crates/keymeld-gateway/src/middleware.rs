use axum::{
    extract::{MatchedPath, State},
    http::Request,
    middleware::Next,
    response::IntoResponse,
};
use std::time::{Duration, Instant};

use crate::handlers::AppState;

/// Requests slower than this are logged as WARN.
const SLOW_REQUEST: Duration = Duration::from_secs(1);
/// Confidential requests wait on an enclave round trip, which normally takes
/// about a second, so only flag ones well past that.
const SLOW_CONFIDENTIAL_REQUEST: Duration = Duration::from_secs(5);

fn slow_threshold(path: &str) -> Duration {
    if path == "/api/v1/confidential" {
        SLOW_CONFIDENTIAL_REQUEST
    } else {
        SLOW_REQUEST
    }
}

pub async fn metrics_middleware(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> impl IntoResponse {
    let start = Instant::now();
    let method = req.method().to_string();
    let matched = req
        .extensions()
        .get::<MatchedPath>()
        .map(|matched_path| matched_path.as_str().to_string());
    let path = matched
        .clone()
        .unwrap_or_else(|| req.uri().path().to_string());

    let response = next.run(req).await;
    let status_code = response.status().as_u16();
    let duration = start.elapsed();

    state
        .metrics
        .record_api_request(&path, &method, status_code);
    // Unmatched paths share one label so probes cannot grow the histogram.
    state.metrics.record_api_request_duration(
        matched.as_deref().unwrap_or("unmatched"),
        &method,
        duration,
    );

    if duration > slow_threshold(&path) {
        tracing::warn!(
            path = %path,
            method = %method,
            status_code = status_code,
            duration_seconds = duration.as_secs_f64(),
            "Slow API request detected"
        );
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidential_relay_has_a_longer_slow_threshold() {
        assert_eq!(
            slow_threshold("/api/v1/confidential"),
            SLOW_CONFIDENTIAL_REQUEST
        );
        assert_eq!(slow_threshold("/api/v1/enclaves"), SLOW_REQUEST);
        assert!(Duration::from_millis(1130) < slow_threshold("/api/v1/confidential"));
    }
}
