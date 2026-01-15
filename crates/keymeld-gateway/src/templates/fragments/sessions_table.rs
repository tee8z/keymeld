use maud::{html, Markup};

use super::session_row::{session_row, SessionView};

/// Sessions table fragment with auto-refresh
pub fn sessions_table(sessions: &[SessionView], show_refresh: bool) -> Markup {
    html! {
        div class="box" {
            div class="is-flex is-justify-content-space-between is-align-items-center mb-4 is-flex-wrap-wrap" {
                h2 class="title is-5 mb-0" { "Sessions" }

                @if show_refresh {
                    button class="button is-small is-light refresh-btn"
                           hx-get="/fragments/sessions-rows"
                           hx-target="#sessions-tbody"
                           hx-swap="innerHTML" {
                        span class="icon is-small" {
                            (refresh_icon())
                        }
                        span { "Refresh" }
                    }
                }
            }

            @if sessions.is_empty() {
                div class="has-text-centered has-text-grey py-6" {
                    p class="is-size-5" { "No sessions found" }
                    p class="is-size-7" { "Sessions will appear here when created via the API." }
                }
            } @else {
                div class="table-container" {
                    table class="table is-fullwidth is-striped is-hoverable" {
                        thead {
                            tr {
                                th { "ID" }
                                th { "Type" }
                                th { "State" }
                                th { "Progress" }
                                th class="is-hidden-mobile" { "Enclave" }
                                th class="is-hidden-mobile" { "Created" }
                                th { "Expires" }
                            }
                        }
                        tbody id="sessions-tbody"
                              hx-get="/fragments/sessions-rows"
                              hx-trigger="every 1s"
                              hx-swap="innerHTML" {
                            @for session in sessions {
                                (session_row(session))
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Just the table rows - used for HTMX partial updates
pub fn sessions_table_rows(sessions: &[SessionView]) -> Markup {
    html! {
        @for session in sessions {
            (session_row(session))
        }
    }
}

fn refresh_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" {
            polyline points="23 4 23 10 17 10" {}
            polyline points="1 20 1 14 7 14" {}
            path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" {}
        }
    }
}
