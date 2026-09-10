pub mod harness;

pub use harness::*;

/// Configure examples with the same explicit trust policy as the gateway channel.
pub fn client_builder(
    gateway_url: &str,
    user_id: keymeld_sdk::UserId,
) -> anyhow::Result<keymeld_sdk::KeyMeldClientBuilder> {
    let builder = keymeld_sdk::KeyMeldClient::builder(gateway_url, user_id);
    let mut measurements = std::collections::BTreeMap::new();
    for name in ["PCR0", "PCR8"] {
        if let Ok(value) = std::env::var(format!("KEYMELD_ENCLAVE_{name}")) {
            if !value.trim().is_empty() {
                measurements.insert(name.to_string(), value);
            }
        }
    }
    if !measurements.is_empty() {
        Ok(
            builder.attestation_policy(keymeld_sdk::AttestationPolicy::from_hex_measurements(
                &measurements,
            )?),
        )
    } else if std::env::var("KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES").as_deref() == Ok("true")
    {
        Ok(builder.dangerous_trust_unattested_enclaves())
    } else {
        anyhow::bail!("Set KEYMELD_ENCLAVE_PCR0/PCR8 from a trusted build, or explicitly set KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES=true for simulated enclaves")
    }
}
