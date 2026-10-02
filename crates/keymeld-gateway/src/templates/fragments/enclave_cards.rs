use maud::{html, Markup};

#[derive(Clone)]
pub struct EnclaveView {
    pub id: u32,
    pub is_healthy: Option<bool>,
    pub public_key: Option<String>,
    pub key_epoch: Option<u64>,
    pub active_sessions: Option<u32>,
    pub observation: Option<crate::enclave::observability::PublicObservation>,
    pub deployment: Option<(String, String)>,
    pub connections: Option<usize>,
    pub in_flight: Option<usize>,
    pub failure_rate: Option<f64>,
    pub relay: (f64, f64),
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
                    span class=(if enclave.is_healthy == Some(true) { "health-indicator is-healthy" } else { "health-indicator is-unhealthy" }) {}
                    span class=(if enclave.is_healthy == Some(true) { "has-text-success" } else { "has-text-danger" }) {
                        @if enclave.is_healthy == Some(true) { "Healthy" } @else if enclave.is_healthy == Some(false) { "Unhealthy" } @else { "Unknown / stale" }
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
                    div class="info-label" { "Enclave sessions" }
                    div class="info-value" { @if let Some(count) = enclave.active_sessions { (count) } @else { "Unknown" } }
                }
            }

            @if let Some((component, version)) = &enclave.deployment {
                p { strong { (component) } " · " (version) }
                p class="is-size-7" { "Deployment configuration; not attested build identity." }
            } @else { p class="is-size-7" { "Enclave build is not reported by this deployment." } }
            p class="is-size-7" { "Sessions reported by the enclave include confidential work; the gateway session list does not." }
            p { (format!("{:.0}", enclave.relay.0)) " confidential responses · " (format!("{:.0}", enclave.relay.1)) " transport failures" }
            p class="is-size-7" { "Since gateway startup. An encrypted response can contain a private application error." }
            details class="mt-3" {
                summary { "Connection and observation details" }
                dl {
                    dt { "Connections" } dd { @if let Some(v) = enclave.connections { (v) } @else { "Unknown" } }
                    dt { "Requests in flight" } dd { @if let Some(v) = enclave.in_flight { (v) } @else { "Unknown" } }
                    dt { "Recent transport failure rate" } dd { @if let Some(v) = enclave.failure_rate { (format!("{v:.1}%")) } @else { "Unknown" } }
                    @if let Some(o) = &enclave.observation {
                        dt { "Public info observed (UTC)" } dd { (time::OffsetDateTime::from_unix_timestamp(o.observed_at).ok().and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok()).unwrap_or_else(|| "Unknown".into())) }
                        dt { "Uptime at observation" } dd { (o.uptime_seconds) " s" }
                    }
                }
                p class="is-size-7" { "For failures, inspect the gateway connection and enclave logs, then the application's entry trace. Transport success does not prove a signing operation succeeded." }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_enclave_observation_is_unknown_and_relay_response_is_not_signing_success() {
        let view = EnclaveView {
            id: 2,
            is_healthy: None,
            public_key: None,
            key_epoch: None,
            active_sessions: None,
            observation: None,
            deployment: Some(("coordinator-verifier".into(), "2.15.3".into())),
            connections: None,
            in_flight: None,
            failure_rate: None,
            relay: (12.0, 1.0),
        };
        let html = enclave_card(&view).into_string();
        assert!(html.contains("Unknown / stale"));
        assert!(html.contains("Enclave sessions</div><div class=\"info-value\">Unknown"));
        assert!(html.contains("12 confidential responses"));
        assert!(html.contains("private application error"));
        assert!(html.contains("not attested build identity"));
    }
}
