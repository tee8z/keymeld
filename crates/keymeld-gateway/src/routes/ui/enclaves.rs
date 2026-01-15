use axum::{extract::State, response::Html};
use keymeld_core::identifiers::EnclaveId;

use crate::{
    handlers::AppState,
    templates::{fragments::EnclaveView, pages::enclaves_page},
};

/// Handler for enclaves page (GET /enclaves)
pub async fn enclaves_handler(State(state): State<AppState>) -> Html<String> {
    let enclaves = build_enclave_views(&state).await;
    Html(enclaves_page(&enclaves).into_string())
}

pub async fn build_enclave_views(state: &AppState) -> Vec<EnclaveView> {
    let enclave_ids = state.enclave_manager.get_all_enclave_ids();
    let enclave_health = state.db.get_all_enclave_health().await.unwrap_or_default();

    let mut views = Vec::new();

    for id in enclave_ids {
        let id_u32 = id.as_u32();
        let health_info = enclave_health
            .iter()
            .find(|h| h.enclave_id as u32 == id_u32);

        let is_healthy = health_info.map(|h| h.is_healthy).unwrap_or(false);
        let public_key = health_info.map(|h| h.public_key.clone());
        let key_epoch = health_info.map(|h| h.key_epoch as u64);

        // Count active sessions for this enclave
        let active_sessions = count_active_sessions_for_enclave(state, &id).await;

        views.push(EnclaveView {
            id: id_u32,
            is_healthy,
            public_key,
            key_epoch,
            active_sessions,
        });
    }

    views.sort_by_key(|e| e.id);
    views
}

async fn count_active_sessions_for_enclave(state: &AppState, enclave_id: &EnclaveId) -> usize {
    // This is a simple count - could be optimized with a dedicated query
    let mut count = 0;

    if let Ok(keygen_sessions) = state.db.list_keygen_sessions(None).await {
        count += keygen_sessions
            .iter()
            .filter(|s| s.coordinator_enclave_id() == Some(*enclave_id))
            .filter(|s| {
                !matches!(
                    s,
                    crate::session::keygen::KeygenSessionStatus::Completed(_)
                        | crate::session::keygen::KeygenSessionStatus::Failed(_)
                )
            })
            .count();
    }

    // Note: Signing sessions don't have a single coordinator enclave - they use
    // inherited_enclave_epochs from the keygen session. We only count keygen sessions here.

    count
}
