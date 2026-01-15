use maud::{html, Markup};

#[derive(Clone)]
pub struct SessionView {
    pub id: String,
    pub session_type: SessionType,
    pub state: SessionState,
    pub participants_registered: usize,
    pub participants_required: usize,
    pub enclave_id: Option<u32>,
    pub created_at: String,
    pub expires_in: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    Keygen,
    Signing,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Reserved,
    CollectingParticipants,
    Initializing,
    Processing,
    Completed,
    Failed,
}

impl SessionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionType::Keygen => "Keygen",
            SessionType::Signing => "Signing",
        }
    }

    pub fn tag_class(&self) -> &'static str {
        match self {
            SessionType::Keygen => "tag is-keygen",
            SessionType::Signing => "tag is-signing",
        }
    }
}

impl SessionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionState::Reserved => "Reserved",
            SessionState::CollectingParticipants => "Collecting",
            SessionState::Initializing => "Initializing",
            SessionState::Processing => "Processing",
            SessionState::Completed => "Completed",
            SessionState::Failed => "Failed",
        }
    }

    pub fn tag_class(&self) -> &'static str {
        match self {
            SessionState::Reserved => "tag is-reserved",
            SessionState::CollectingParticipants => "tag is-collecting",
            SessionState::Initializing => "tag is-initializing",
            SessionState::Processing => "tag is-initializing",
            SessionState::Completed => "tag is-completed",
            SessionState::Failed => "tag is-failed",
        }
    }
}

/// Single session row for the sessions table
pub fn session_row(session: &SessionView) -> Markup {
    let truncated_id = if session.id.len() > 8 {
        format!("{}...", &session.id[..8])
    } else {
        session.id.clone()
    };

    let progress = format!(
        "{}/{}",
        session.participants_registered, session.participants_required
    );
    let progress_complete = session.participants_registered >= session.participants_required;

    html! {
        tr class="is-clickable"
           hx-get=(format!("/sessions/{}", session.id))
           hx-target="#main-content"
           hx-push-url="true" {
            td {
                span class="session-id truncate" title=(session.id) {
                    (truncated_id)
                }
            }
            td {
                span class=(session.session_type.tag_class()) {
                    (session.session_type.as_str())
                }
            }
            td {
                span class=(session.state.tag_class()) {
                    (session.state.as_str())
                }
            }
            td {
                span class=(if progress_complete { "progress-text is-complete" } else { "progress-text" }) {
                    (progress)
                    @if progress_complete {
                        " " (checkmark_icon())
                    }
                }
            }
            td class="is-hidden-mobile" {
                @if let Some(enclave_id) = session.enclave_id {
                    span class="tag is-light" { "enc-" (enclave_id) }
                } @else {
                    span class="has-text-grey" { "-" }
                }
            }
            td class="is-hidden-mobile" {
                span class="timestamp" { (session.created_at) }
            }
            td {
                @if let Some(ref expires) = session.expires_in {
                    @if expires.contains("expired") {
                        span class="expires-soon" { (expires) }
                    } @else {
                        span class="timestamp" { (expires) }
                    }
                } @else {
                    span class="has-text-grey" { "-" }
                }
            }
        }
    }
}

fn checkmark_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"
            stroke-linejoin="round" style="vertical-align: middle;" {
            polyline points="20 6 9 17 4 12" {}
        }
    }
}
