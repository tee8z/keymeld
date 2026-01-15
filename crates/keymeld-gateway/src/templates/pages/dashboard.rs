use maud::{html, Markup};

use crate::templates::{
    fragments::{enclave_cards, sessions_table, AdminStats, EnclaveView, SessionView},
    layouts::{base, CurrentPage, PageConfig},
};

/// Dashboard page content (for HTMX partial updates)
pub fn dashboard_content(
    stats: &AdminStats,
    recent_sessions: &[SessionView],
    enclaves: &[EnclaveView],
) -> Markup {
    html! {
        // Stats cards with auto-refresh
        div id="stats-cards"
            hx-get="/fragments/stats"
            hx-trigger="every 1s"
            hx-swap="innerHTML" {
            (crate::templates::fragments::stats_cards(stats))
        }

        // Recent sessions
        div class="mt-5" {
            h2 class="title is-5" { "Recent Sessions" }
            (sessions_table(recent_sessions, true))
        }

        // Enclave overview
        div class="mt-5" {
            div class="is-flex is-justify-content-space-between is-align-items-center mb-4" {
                h2 class="title is-5 mb-0" { "Enclave Overview" }
                a href="/enclaves"
                  hx-get="/enclaves"
                  hx-target="#main-content"
                  hx-push-url="true"
                  class="button is-small is-light" {
                    "View All"
                }
            }
            (enclave_cards(enclaves))
        }
    }
}

/// Full dashboard page with layout
pub fn dashboard_page(
    stats: &AdminStats,
    recent_sessions: &[SessionView],
    enclaves: &[EnclaveView],
) -> Markup {
    let config = PageConfig {
        title: "KeyMeld Admin - Dashboard",
        current_page: CurrentPage::Dashboard,
    };

    base(&config, dashboard_content(stats, recent_sessions, enclaves))
}
