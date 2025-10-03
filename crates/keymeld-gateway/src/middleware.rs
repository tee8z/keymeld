use axum::{
    extract::{MatchedPath, State},
    http::Request,
    middleware::Next,
    response::IntoResponse,
};
use std::time::Instant;

use crate::handlers::AppState;

pub async fn metrics_middleware(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> impl IntoResponse {
    let start = Instant::now();
    let method = req.method().to_string();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|matched_path| matched_path.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    let response = next.run(req).await;
    let status_code = response.status().as_u16();
    let duration = start.elapsed();

    state
        .metrics
        .record_api_request(&path, &method, status_code);

    if duration.as_secs_f64() > 1.0 {
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
