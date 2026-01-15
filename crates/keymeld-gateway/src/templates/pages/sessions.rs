use maud::{html, Markup};

use crate::templates::{
    fragments::{sessions_table, SessionView},
    layouts::{base, CurrentPage, PageConfig},
};

/// Sessions page content (for HTMX partial updates)
pub fn sessions_content(sessions: &[SessionView]) -> Markup {
    html! {
        h2 class="title is-4" { "All Sessions" }
        p class="subtitle is-6 has-text-grey" {
            "View and monitor keygen and signing sessions"
        }
        (sessions_table(sessions, true))
    }
}

/// Full sessions page with layout
pub fn sessions_page(sessions: &[SessionView]) -> Markup {
    let config = PageConfig {
        title: "KeyMeld Admin - Sessions",
        current_page: CurrentPage::Sessions,
    };

    base(&config, sessions_content(sessions))
}

/// Session detail view
#[derive(Clone)]
pub struct SessionDetailView {
    pub id: String,
    pub session_type: String,
    pub state: String,
    pub state_class: String,
    pub enclave_id: Option<u32>,
    pub participants_registered: usize,
    pub participants_required: usize,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub participants: Vec<ParticipantView>,
}

#[derive(Clone)]
pub struct ParticipantView {
    pub user_id: String,
    pub public_key: Option<String>,
    pub enclave_id: Option<u32>,
    pub approved: bool,
}

/// Session detail page content
pub fn session_detail_content(session: &SessionDetailView) -> Markup {
    let progress = format!(
        "{}/{}",
        session.participants_registered, session.participants_required
    );
    let progress_complete = session.participants_registered >= session.participants_required;

    html! {
        // Back button and title
        div class="session-detail-header" {
            a href="/sessions"
              hx-get="/sessions"
              hx-target="#main-content"
              hx-push-url="true"
              class="button is-small back-btn" {
                (back_icon())
                span class="ml-1" { "Back" }
            }
            h2 class="title is-4 mb-0" { "Session Details" }
        }

        div class="columns" {
            // Session info card
            div class="column is-6" {
                div class="box" {
                    h3 class="title is-6" { "Session Info" }

                    div class="field" {
                        label class="label is-small" { "Session ID" }
                        div class="control" {
                            input class="input is-small" type="text" readonly value=(session.id);
                        }
                    }

                    div class="columns is-mobile" {
                        div class="column" {
                            label class="label is-small" { "Type" }
                            span class=(format!("tag {}", if session.session_type == "Keygen" { "is-keygen" } else { "is-signing" })) {
                                (session.session_type)
                            }
                        }
                        div class="column" {
                            label class="label is-small" { "State" }
                            span class=(format!("tag {}", session.state_class)) {
                                (session.state)
                            }
                        }
                    }

                    div class="columns is-mobile" {
                        div class="column" {
                            label class="label is-small" { "Progress" }
                            span class=(if progress_complete { "progress-text is-complete" } else { "progress-text" }) {
                                (progress)
                                @if progress_complete { " " (checkmark_icon()) }
                            }
                        }
                        div class="column" {
                            label class="label is-small" { "Enclave" }
                            @if let Some(enclave_id) = session.enclave_id {
                                span class="tag is-light" { "enc-" (enclave_id) }
                            } @else {
                                span class="has-text-grey" { "Not assigned" }
                            }
                        }
                    }
                }
            }

            // Timeline card
            div class="column is-6" {
                div class="box" {
                    h3 class="title is-6" { "Timeline" }

                    div class="field" {
                        label class="label is-small" { "Created" }
                        p class="timestamp" { (session.created_at) }
                    }

                    @if let Some(ref expires) = session.expires_at {
                        div class="field" {
                            label class="label is-small" { "Expires" }
                            p class="timestamp" { (expires) }
                        }
                    }
                }
            }
        }

        // Participants table
        div class="box mt-4" {
            h3 class="title is-6" { "Participants" }

            @if session.participants.is_empty() {
                p class="has-text-grey" { "No participants registered yet." }
            } @else {
                div class="table-container" {
                    table class="table is-fullwidth is-striped" {
                        thead {
                            tr {
                                th { "User ID" }
                                th class="is-hidden-mobile" { "Public Key" }
                                th { "Enclave" }
                                th { "Status" }
                            }
                        }
                        tbody {
                            @for participant in &session.participants {
                                tr class="participant-row" {
                                    td {
                                        span class="session-id" {
                                            @if participant.user_id.len() > 8 {
                                                (format!("{}...", &participant.user_id[..8]))
                                            } @else {
                                                (participant.user_id)
                                            }
                                        }
                                    }
                                    td class="is-hidden-mobile" {
                                        @if let Some(ref pubkey) = participant.public_key {
                                            span class="pubkey" {
                                                @if pubkey.len() > 20 {
                                                    (format!("{}...", &pubkey[..20]))
                                                } @else {
                                                    (pubkey)
                                                }
                                            }
                                        } @else {
                                            span class="has-text-grey" { "-" }
                                        }
                                    }
                                    td {
                                        @if let Some(enclave_id) = participant.enclave_id {
                                            span class="tag is-light is-small" { "enc-" (enclave_id) }
                                        } @else {
                                            span class="has-text-grey" { "-" }
                                        }
                                    }
                                    td {
                                        @if participant.approved {
                                            span class="tag is-success is-small" { "Approved" }
                                        } @else {
                                            span class="tag is-warning is-small" { "Pending" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Full session detail page with layout
pub fn session_detail_page(session: &SessionDetailView) -> Markup {
    let config = PageConfig {
        title: &format!(
            "KeyMeld Admin - Session {}",
            &session.id[..8.min(session.id.len())]
        ),
        current_page: CurrentPage::Sessions,
    };

    base(&config, session_detail_content(session))
}

fn back_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
            stroke-linejoin="round" {
            line x1="19" y1="12" x2="5" y2="12" {}
            polyline points="12 19 5 12 12 5" {}
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
