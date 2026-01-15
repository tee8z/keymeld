use maud::{html, Markup};

#[derive(Clone)]
pub struct EnclaveView {
    pub id: u32,
    pub is_healthy: bool,
    pub public_key: Option<String>,
    pub key_epoch: Option<u64>,
    pub active_sessions: usize,
}

/// Enclave cards grid
pub fn enclave_cards(enclaves: &[EnclaveView]) -> Markup {
    html! {
        div class="columns is-multiline" {
            @for enclave in enclaves {
                div class="column is-12-mobile is-6-tablet is-4-desktop" {
                    (enclave_card(enclave))
                }
            }
        }
    }
}

/// Single enclave card
pub fn enclave_card(enclave: &EnclaveView) -> Markup {
    let truncated_pubkey = enclave.public_key.as_ref().map(|pk| {
        if pk.len() > 20 {
            format!("{}...{}", &pk[..10], &pk[pk.len() - 10..])
        } else {
            pk.clone()
        }
    });

    html! {
        div class="box enclave-card" {
            div class="enclave-header" {
                div {
                    span class="enclave-id" { "Enclave " (enclave.id) }
                }
                div {
                    span class=(if enclave.is_healthy { "health-indicator is-healthy" } else { "health-indicator is-unhealthy" }) {}
                    span class=(if enclave.is_healthy { "has-text-success" } else { "has-text-danger" }) {
                        @if enclave.is_healthy { "Healthy" } @else { "Unhealthy" }
                    }
                }
            }

            div class="columns is-multiline is-mobile" {
                div class="column is-6" {
                    div class="info-label" { "Key Epoch" }
                    div class="info-value" {
                        @if let Some(epoch) = enclave.key_epoch {
                            (epoch)
                        } @else {
                            "-"
                        }
                    }
                }
                div class="column is-6" {
                    div class="info-label" { "Active Sessions" }
                    div class="info-value" { (enclave.active_sessions) }
                }
            }

            @if let Some(ref pubkey) = enclave.public_key {
                div class="mt-3" {
                    div class="info-label" {
                        "Public Key"
                        button class="copy-btn ml-2" onclick=(format!("navigator.clipboard.writeText('{}'); this.classList.add('copied'); setTimeout(() => this.classList.remove('copied'), 1000);", pubkey)) title="Copy full key" {
                            (copy_icon())
                        }
                    }
                    div class="info-value" title=(pubkey) {
                        @if let Some(ref truncated) = truncated_pubkey {
                            (truncated)
                        }
                    }
                }
            }
        }
    }
}

fn copy_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
            stroke-linejoin="round" {
            rect x="9" y="9" width="13" height="13" rx="2" ry="2" {}
            path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" {}
        }
    }
}
