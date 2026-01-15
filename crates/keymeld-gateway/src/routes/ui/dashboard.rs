use axum::{extract::State, http::HeaderMap, response::Html};

use crate::{
    handlers::AppState,
    templates::{
        fragments::AdminStats,
        pages::{dashboard_content, dashboard_page},
    },
};

use super::{enclaves::build_enclave_views, sessions::build_session_views};

/// Handler for dashboard page (GET /)
/// Returns full page for normal requests, just content for HTMX requests
pub async fn dashboard_handler(headers: HeaderMap, State(state): State<AppState>) -> Html<String> {
    let stats = build_admin_stats(&state).await;
    let recent_sessions = build_session_views(&state, Some(10)).await;
    let enclaves = build_enclave_views(&state).await;

    // Check if this is an HTMX request
    if headers.contains_key("hx-request") {
        Html(dashboard_content(&stats, &recent_sessions, &enclaves).into_string())
    } else {
        Html(dashboard_page(&stats, &recent_sessions, &enclaves).into_string())
    }
}

pub async fn build_admin_stats(state: &AppState) -> AdminStats {
    // Get enclave health
    let enclave_health = state.db.get_all_enclave_health().await.unwrap_or_default();
    let total_enclaves = state.enclave_manager.get_all_enclave_ids().len();
    let healthy_enclaves = enclave_health.iter().filter(|e| e.is_healthy).count();

    // Get session stats
    let db_stats = state.db.get_stats().await.unwrap_or_default();

    AdminStats {
        healthy_enclaves,
        total_enclaves,
        active_keygen_sessions: db_stats.active_keygen_sessions as usize,
        active_signing_sessions: db_stats.active_signing_sessions as usize,
        total_sessions: db_stats.total_keygen_sessions as usize
            + db_stats.total_signing_sessions as usize,
    }
}
