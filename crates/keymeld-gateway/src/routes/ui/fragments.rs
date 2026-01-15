use axum::{extract::State, response::Html};

use crate::{
    handlers::AppState,
    templates::fragments::{enclave_cards, sessions_table_rows, stats_cards},
};

use super::{
    dashboard::build_admin_stats, enclaves::build_enclave_views, sessions::build_session_views,
};

/// Handler for stats fragment (GET /fragments/stats)
pub async fn stats_fragment_handler(State(state): State<AppState>) -> Html<String> {
    let stats = build_admin_stats(&state).await;
    Html(stats_cards(&stats).into_string())
}

/// Handler for sessions rows fragment (GET /fragments/sessions-rows)
pub async fn sessions_rows_handler(State(state): State<AppState>) -> Html<String> {
    let sessions = build_session_views(&state, None).await;
    Html(sessions_table_rows(&sessions).into_string())
}

/// Handler for enclaves fragment (GET /fragments/enclaves)
pub async fn enclaves_fragment_handler(State(state): State<AppState>) -> Html<String> {
    let enclaves = build_enclave_views(&state).await;
    Html(enclave_cards(&enclaves).into_string())
}
