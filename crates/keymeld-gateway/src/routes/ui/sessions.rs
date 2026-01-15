use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Html,
};
use keymeld_core::identifiers::SessionId;
use std::collections::BTreeMap;
use time::OffsetDateTime;

use crate::{
    handlers::AppState,
    templates::{
        fragments::{session_row::SessionState, session_row::SessionType, SessionView},
        pages::{
            session_detail_page,
            sessions::{ParticipantView, SessionDetailView},
            sessions_content, sessions_page,
        },
    },
};

/// Handler for sessions page (GET /sessions)
/// Returns full page for normal requests, just content for HTMX requests
pub async fn sessions_handler(headers: HeaderMap, State(state): State<AppState>) -> Html<String> {
    let sessions = build_session_views(&state, None).await;

    if headers.contains_key("hx-request") {
        Html(sessions_content(&sessions).into_string())
    } else {
        Html(sessions_page(&sessions).into_string())
    }
}

/// Handler for session detail page (GET /sessions/{session_id})
/// Returns full page for normal requests, just content for HTMX requests
pub async fn session_detail_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Html<String> {
    let is_htmx = headers.contains_key("hx-request");

    let session_id_parsed = match SessionId::parse(&session_id) {
        Ok(id) => id,
        Err(_) => {
            return Html(crate::templates::pages::sessions_page(&[]).into_string());
        }
    };

    // Try keygen session first
    if let Ok(Some(keygen_session)) = state.db.get_keygen_session_by_id(&session_id_parsed).await {
        let empty_map = BTreeMap::new();
        let registered = keygen_session
            .registered_participants()
            .unwrap_or(&empty_map);
        let participants: Vec<ParticipantView> = registered
            .iter()
            .map(|(user_id, data)| ParticipantView {
                user_id: user_id.to_string(),
                public_key: if data.auth_pubkey.is_empty() {
                    None
                } else {
                    Some(hex::encode(&data.auth_pubkey))
                },
                enclave_id: Some(data.enclave_id.as_u32()),
                approved: true, // Keygen participants are "approved" once registered
            })
            .collect();

        let (state_str, state_class) = keygen_state_info(&keygen_session);

        let detail = SessionDetailView {
            id: session_id.clone(),
            session_type: "Keygen".to_string(),
            state: state_str.to_string(),
            state_class: state_class.to_string(),
            enclave_id: keygen_session.coordinator_enclave_id().map(|e| e.as_u32()),
            participants_registered: registered.len(),
            participants_required: keygen_session.expected_participants_count(),
            created_at: format_timestamp(keygen_session.created_at() as i64),
            expires_at: keygen_session
                .expires_at()
                .map(|t| format_timestamp(t as i64)),
            participants,
        };

        return if is_htmx {
            Html(crate::templates::pages::session_detail_content(&detail).into_string())
        } else {
            Html(session_detail_page(&detail).into_string())
        };
    }

    // Try signing session
    if let Ok(Some(signing_session)) = state.db.get_signing_session_by_id(&session_id_parsed).await
    {
        let empty_map = BTreeMap::new();
        let registered = signing_session
            .registered_participants()
            .unwrap_or(&empty_map);
        let approvals = signing_session.approved_participants();
        let participants: Vec<ParticipantView> = registered
            .iter()
            .map(|(user_id, data)| {
                let approved = approvals.contains(user_id);
                ParticipantView {
                    user_id: user_id.to_string(),
                    public_key: if data.auth_pubkey.is_empty() {
                        None
                    } else {
                        Some(hex::encode(&data.auth_pubkey))
                    },
                    enclave_id: Some(data.enclave_id.as_u32()),
                    approved,
                }
            })
            .collect();

        let (state_str, state_class) = signing_state_info(&signing_session);
        let (_, num_expected, _, _, _) = signing_session.extract_status_info();

        let detail = SessionDetailView {
            id: session_id.clone(),
            session_type: "Signing".to_string(),
            state: state_str.to_string(),
            state_class: state_class.to_string(),
            enclave_id: None, // Signing sessions don't have a single coordinator enclave
            participants_registered: registered.len(),
            participants_required: num_expected,
            created_at: format_timestamp(signing_session.created_at() as i64),
            expires_at: signing_session
                .expires_at()
                .map(|t| format_timestamp(t as i64)),
            participants,
        };

        return if is_htmx {
            Html(crate::templates::pages::session_detail_content(&detail).into_string())
        } else {
            Html(session_detail_page(&detail).into_string())
        };
    }

    // Session not found - return to sessions list
    Html(sessions_page(&[]).into_string())
}

pub async fn build_session_views(state: &AppState, limit: Option<usize>) -> Vec<SessionView> {
    let mut sessions = Vec::new();

    // Get keygen sessions
    if let Ok(keygen_sessions) = state.db.list_keygen_sessions(limit).await {
        for ks in keygen_sessions {
            let (session_state, _) = keygen_state_to_enum(&ks);
            let registered_count = ks.registered_participants().map(|p| p.len()).unwrap_or(0);
            sessions.push(SessionView {
                id: ks.session_id().to_string(),
                session_type: SessionType::Keygen,
                state: session_state,
                participants_registered: registered_count,
                participants_required: ks.expected_participants_count(),
                enclave_id: ks.coordinator_enclave_id().map(|e| e.as_u32()),
                created_at: format_timestamp(ks.created_at() as i64),
                expires_in: ks.expires_at().map(|t| format_expires_in(t as i64)),
            });
        }
    }

    // Get signing sessions
    if let Ok(signing_sessions) = state.db.list_signing_sessions(limit).await {
        for ss in signing_sessions {
            let (session_state, _) = signing_state_to_enum(&ss);
            let (_, num_expected, _, _, _) = ss.extract_status_info();
            let approvals_count = ss.approved_participants().len();
            sessions.push(SessionView {
                id: ss.session_id().to_string(),
                session_type: SessionType::Signing,
                state: session_state,
                participants_registered: approvals_count,
                participants_required: num_expected,
                enclave_id: None, // Signing sessions don't have a single coordinator enclave
                created_at: format_timestamp(ss.created_at() as i64),
                expires_in: ss.expires_at().map(|t| format_expires_in(t as i64)),
            });
        }
    }

    // Sort by created_at descending (most recent first)
    sessions.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    // Apply limit if specified
    if let Some(limit) = limit {
        sessions.truncate(limit);
    }

    sessions
}

fn keygen_state_info(
    status: &crate::session::keygen::KeygenSessionStatus,
) -> (&'static str, &'static str) {
    use crate::session::keygen::KeygenSessionStatus;
    match status {
        KeygenSessionStatus::Reserved(_) => ("Reserved", "is-reserved"),
        KeygenSessionStatus::CollectingParticipants(_) => ("Collecting", "is-collecting"),
        KeygenSessionStatus::Completed(_) => ("Completed", "is-completed"),
        KeygenSessionStatus::Failed(_) => ("Failed", "is-failed"),
    }
}

fn signing_state_info(
    status: &crate::session::signing::SigningSessionStatus,
) -> (&'static str, &'static str) {
    use crate::session::signing::SigningSessionStatus;
    match status {
        SigningSessionStatus::CollectingParticipants(_) => ("Collecting", "is-collecting"),
        SigningSessionStatus::InitializingSession(_) => ("Initializing", "is-initializing"),
        SigningSessionStatus::DistributingNonces(_) => ("Distributing", "is-distributing"),
        SigningSessionStatus::FinalizingSignature(_) => ("Finalizing", "is-finalizing"),
        SigningSessionStatus::Completed(_) => ("Completed", "is-completed"),
        SigningSessionStatus::Failed(_) => ("Failed", "is-failed"),
    }
}

fn keygen_state_to_enum(
    status: &crate::session::keygen::KeygenSessionStatus,
) -> (SessionState, &'static str) {
    use crate::session::keygen::KeygenSessionStatus;
    match status {
        KeygenSessionStatus::Reserved(_) => (SessionState::Reserved, "is-reserved"),
        KeygenSessionStatus::CollectingParticipants(_) => {
            (SessionState::CollectingParticipants, "is-collecting")
        }
        KeygenSessionStatus::Completed(_) => (SessionState::Completed, "is-completed"),
        KeygenSessionStatus::Failed(_) => (SessionState::Failed, "is-failed"),
    }
}

fn signing_state_to_enum(
    status: &crate::session::signing::SigningSessionStatus,
) -> (SessionState, &'static str) {
    use crate::session::signing::SigningSessionStatus;
    match status {
        SigningSessionStatus::CollectingParticipants(_) => {
            (SessionState::CollectingParticipants, "is-collecting")
        }
        SigningSessionStatus::InitializingSession(_) => {
            (SessionState::Initializing, "is-initializing")
        }
        SigningSessionStatus::DistributingNonces(_) => (SessionState::Processing, "is-processing"),
        SigningSessionStatus::FinalizingSignature(_) => (SessionState::Processing, "is-processing"),
        SigningSessionStatus::Completed(_) => (SessionState::Completed, "is-completed"),
        SigningSessionStatus::Failed(_) => (SessionState::Failed, "is-failed"),
    }
}

fn format_timestamp(ts: i64) -> String {
    if let Ok(dt) = OffsetDateTime::from_unix_timestamp(ts) {
        let format =
            time::format_description::parse("[year]-[month]-[day] [hour]:[minute]").unwrap();
        dt.format(&format).unwrap_or_else(|_| ts.to_string())
    } else {
        ts.to_string()
    }
}

fn format_expires_in(expires_at: i64) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let diff = expires_at - now;

    if diff < 0 {
        "expired".to_string()
    } else if diff < 60 {
        format!("{}s", diff)
    } else if diff < 3600 {
        format!("{}m", diff / 60)
    } else if diff < 86400 {
        format!("{}h", diff / 3600)
    } else {
        format!("{}d", diff / 86400)
    }
}
