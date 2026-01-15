use maud::{html, Markup};

use crate::templates::{
    fragments::{enclave_cards, EnclaveView},
    layouts::{base, CurrentPage, PageConfig},
};

/// Enclaves page content (for HTMX partial updates)
pub fn enclaves_content(enclaves: &[EnclaveView]) -> Markup {
    html! {
        div class="is-flex is-justify-content-space-between is-align-items-center mb-4 is-flex-wrap-wrap" {
            div {
                h2 class="title is-4 mb-1" { "Enclaves" }
                p class="subtitle is-6 has-text-grey" {
                    "Monitor enclave health and status"
                }
            }
            button class="button is-small is-light refresh-btn"
                   hx-get="/fragments/enclaves"
                   hx-target="#enclaves-grid"
                   hx-swap="innerHTML" {
                span class="icon is-small" { (refresh_icon()) }
                span { "Refresh" }
            }
        }

        div id="enclaves-grid"
            hx-get="/fragments/enclaves"
            hx-trigger="every 1s"
            hx-swap="innerHTML" {
            (enclave_cards(enclaves))
        }
    }
}

/// Full enclaves page with layout
pub fn enclaves_page(enclaves: &[EnclaveView]) -> Markup {
    let config = PageConfig {
        title: "KeyMeld Admin - Enclaves",
        current_page: CurrentPage::Enclaves,
    };

    base(&config, enclaves_content(enclaves))
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
