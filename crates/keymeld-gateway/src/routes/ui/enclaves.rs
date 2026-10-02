use axum::{extract::State, http::HeaderMap, response::Html};

use crate::{
    handlers::AppState,
    templates::{
        fragments::EnclaveView,
        pages::{enclaves_content, enclaves_page},
    },
};

/// Handler for enclaves page (GET /enclaves)
/// Returns full page for normal requests, just content for HTMX requests
pub async fn enclaves_handler(headers: HeaderMap, State(state): State<AppState>) -> Html<String> {
    let enclaves = build_enclave_views(&state).await;

    if headers.contains_key("hx-request") {
        Html(enclaves_content(&enclaves).into_string())
    } else {
        Html(enclaves_page(&enclaves).into_string())
    }
}

pub async fn build_enclave_views(state: &AppState) -> Vec<EnclaveView> {
    let enclave_ids = state.enclave_manager.get_all_enclave_ids();
    let enclave_health = state.db.get_all_enclave_health().await.unwrap_or_default();

    let mut views = Vec::new();
    let connections = state.enclave_manager.get_connection_stats();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    for id in enclave_ids {
        let id_u32 = id.as_u32();
        let health_info = enclave_health
            .iter()
            .find(|h| h.enclave_id as u32 == id_u32);

        let is_healthy = health_info
            .filter(|h| h.expires_at > now)
            .map(|h| h.is_healthy);
        let public_key = health_info.map(|h| h.public_key.clone());
        let key_epoch = health_info.map(|h| h.key_epoch as u64);

        let observation = state.enclave_manager.public_observation(&id);
        let active_sessions = observation
            .as_ref()
            .filter(|o| now.saturating_sub(o.observed_at) <= 30)
            .map(|o| o.active_sessions);
        let connection = connections.get(&id);

        views.push(EnclaveView {
            id: id_u32,
            is_healthy,
            public_key,
            key_epoch,
            active_sessions,
            observation,
            deployment: crate::enclave::observability::deployment().cloned(),
            connections: connection.map(|c| c.active_connections),
            in_flight: connection.map(|c| c.pending_requests_count),
            failure_rate: connection.map(|c| c.prometheus_metrics.failure_rate),
            relay: crate::metrics::confidential_relay_counts(id_u32),
        });
    }

    views.sort_by_key(|e| e.id);
    views
}
