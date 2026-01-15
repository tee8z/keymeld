use maud::{html, Markup};

#[derive(Default)]
pub struct AdminStats {
    pub healthy_enclaves: usize,
    pub total_enclaves: usize,
    pub active_keygen_sessions: usize,
    pub active_signing_sessions: usize,
    pub total_sessions: usize,
}

/// Stats cards for the dashboard
pub fn stats_cards(stats: &AdminStats) -> Markup {
    html! {
        div class="columns is-multiline" {
            div class="column is-3-desktop is-6-tablet" {
                div class="box stat-card" {
                    div class="stat-value" {
                        span class=(if stats.healthy_enclaves == stats.total_enclaves { "has-text-success" } else { "has-text-warning" }) {
                            (stats.healthy_enclaves) "/" (stats.total_enclaves)
                        }
                    }
                    div class="stat-label" { "Enclaves Healthy" }
                }
            }
            div class="column is-3-desktop is-6-tablet" {
                div class="box stat-card" {
                    div class="stat-value" { (stats.active_keygen_sessions + stats.active_signing_sessions) }
                    div class="stat-label" { "Active Sessions" }
                }
            }
            div class="column is-3-desktop is-6-tablet" {
                div class="box stat-card" {
                    div class="stat-value has-text-info" { (stats.active_keygen_sessions) }
                    div class="stat-label" { "Keygen Sessions" }
                }
            }
            div class="column is-3-desktop is-6-tablet" {
                div class="box stat-card" {
                    div class="stat-value has-text-link" { (stats.active_signing_sessions) }
                    div class="stat-label" { "Signing Sessions" }
                }
            }
        }
    }
}
