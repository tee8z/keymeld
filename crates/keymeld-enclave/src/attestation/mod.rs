pub mod nsm;

use keymeld_core::protocol::{AttestationError, DataDecodingError, EnclaveError, InternalError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tracing::warn;

pub use keymeld_core::AttestationDocument;
pub use nsm::{KeyMeldAttestation, NsmClient};

type Result<T> = std::result::Result<T, EnclaveError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfig {
    pub enabled: bool,
    pub max_age_seconds: u64,
    pub required_pcrs: BTreeMap<String, String>,
    pub allow_debug_mode: bool,
    pub generate_attestations: bool,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_age_seconds: 300,
            required_pcrs: BTreeMap::new(),
            allow_debug_mode: false,
            generate_attestations: true,
        }
    }
}

#[derive(Debug)]
pub struct AttestationManager {
    config: AttestationConfig,
    nsm_client: Option<NsmClient>,
    is_debug_mode: bool,
}

impl Clone for AttestationManager {
    fn clone(&self) -> Self {
        let nsm_client = if self.nsm_client.is_some() {
            NsmClient::new().ok()
        } else {
            None
        };

        Self {
            config: self.config.clone(),
            nsm_client,
            is_debug_mode: self.is_debug_mode,
        }
    }
}

impl AttestationManager {
    pub fn new(config: AttestationConfig) -> Result<Self> {
        let nsm_client = if config.enabled {
            match NsmClient::new() {
                Ok(client) => Some(client),
                Err(e) => {
                    warn!("Failed to initialize NSM client: {}", e);
                    if config.generate_attestations {
                        return Err(e.into());
                    }
                    None
                }
            }
        } else {
            None
        };

        let is_debug_mode = if let Some(ref client) = nsm_client {
            nsm::is_debug_mode(client).unwrap_or(false)
        } else {
            false
        };

        if is_debug_mode && !config.allow_debug_mode {
            return Err(EnclaveError::Attestation(
                AttestationError::DebugModeNotAllowed,
            ));
        }

        Ok(Self {
            config,
            nsm_client,
            is_debug_mode,
        })
    }

    pub fn generate_session_attestation(
        &self,
        session_id: &str,
        enclave_public_key: Option<&[u8]>,
    ) -> Result<Option<KeyMeldAttestation>> {
        if !self.config.enabled || !self.config.generate_attestations {
            return Ok(None);
        }

        let nsm_client = self
            .nsm_client
            .as_ref()
            .ok_or(EnclaveError::Internal(InternalError::NsmNotInitialized))?;

        if self.is_debug_mode {
            warn!(
                "Generating debug attestation for session {} - not suitable for production",
                session_id
            );
        }

        let attestation = KeyMeldAttestation::generate(nsm_client, session_id, enclave_public_key)?;

        Ok(Some(attestation))
    }

    pub fn verify_attestation(&self, attestation: &KeyMeldAttestation) -> Result<bool> {
        if !self.config.enabled {
            return Ok(true);
        }

        if !attestation.is_valid(self.config.max_age_seconds) {
            warn!(
                "Attestation for session {} is expired",
                attestation.session_id()
            );
            return Ok(false);
        }

        if !self.config.required_pcrs.is_empty() {
            let pcr_hex_values = attestation.pcr_hex_values();

            for (pcr_name, expected_hex) in &self.config.required_pcrs {
                match pcr_hex_values.get(pcr_name) {
                    Some(actual_hex) if actual_hex == expected_hex => {}
                    Some(actual_hex) => {
                        warn!(
                            "PCR {} verification failed. Expected: {}, Actual: {}",
                            pcr_name, expected_hex, actual_hex
                        );
                        return Ok(false);
                    }
                    None => {
                        warn!("Required PCR {} not found in attestation", pcr_name);
                        return Ok(false);
                    }
                }
            }
        }

        if self.is_debug_mode && !self.config.allow_debug_mode {
            warn!("Debug mode attestation not allowed by configuration");
            return Ok(false);
        }

        // Attestation verification passed
        Ok(true)
    }

    pub fn get_random(&self, num_bytes: u16) -> Result<Vec<u8>> {
        let nsm_client = self
            .nsm_client
            .as_ref()
            .ok_or(EnclaveError::Internal(InternalError::NsmNotInitialized))?;

        nsm_client.get_random(num_bytes).map_err(Into::into)
    }

    pub fn is_debug_mode(&self) -> bool {
        self.is_debug_mode
    }

    pub fn config(&self) -> &AttestationConfig {
        &self.config
    }

    pub fn get_identity_attestation(&self) -> Result<Option<AttestationDocument>> {
        self.get_identity_attestation_with_data(None)
    }

    pub fn get_identity_attestation_with_data(
        &self,
        user_data: Option<&[u8]>,
    ) -> Result<Option<AttestationDocument>> {
        if !self.config.enabled {
            return Ok(None);
        }

        let nsm_client = self
            .nsm_client
            .as_ref()
            .ok_or(EnclaveError::Internal(InternalError::NsmNotInitialized))?;

        let user_data_buf = user_data.map(|data| data.to_vec());

        let attestation =
            nsm_client.get_attestation_document(None, user_data_buf.as_deref(), None)?;
        Ok(Some(attestation))
    }

    #[cfg(test)]
    pub fn mock() -> Self {
        Self {
            config: AttestationConfig {
                enabled: false,
                ..Default::default()
            },
            nsm_client: None,
            is_debug_mode: true,
        }
    }
}

pub mod utils {
    use super::*;

    pub fn pcr_hex_to_bytes(
        hex_values: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, Vec<u8>>> {
        let mut byte_values = BTreeMap::new();

        for (pcr_name, hex_value) in hex_values {
            let bytes = hex::decode(hex_value).map_err(|e| {
                EnclaveError::DataDecoding(DataDecodingError::HexDecode(format!(
                    "Invalid hex for {pcr_name}: {e}"
                )))
            })?;
            byte_values.insert(pcr_name.clone(), bytes);
        }

        Ok(byte_values)
    }

    pub fn parse_build_measurements(measurements_json: &str) -> Result<BTreeMap<String, String>> {
        let measurements: serde_json::Value =
            serde_json::from_str(measurements_json).map_err(|e| {
                EnclaveError::Attestation(AttestationError::MeasurementParsing(format!("{e}")))
            })?;

        let mut pcr_values = BTreeMap::new();

        if let Some(measurements_obj) = measurements.get("Measurements") {
            for i in 0..=8 {
                let pcr_key = format!("PCR{i}");
                if let Some(pcr_value) = measurements_obj.get(&pcr_key) {
                    if let Some(pcr_str) = pcr_value.as_str() {
                        pcr_values.insert(pcr_key, pcr_str.to_string());
                    }
                }
            }
        }

        Ok(pcr_values)
    }

    pub fn validate_pcr_format(pcrs: &BTreeMap<String, Vec<u8>>) -> Result<()> {
        for (pcr_name, pcr_value) in pcrs {
            if pcr_value.len() != 48 {
                return Err(EnclaveError::Attestation(
                    AttestationError::InvalidPcrLength {
                        pcr_name: pcr_name.clone(),
                        actual: pcr_value.len(),
                    },
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_config_default() {
        let config = AttestationConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_age_seconds, 300);
        assert!(config.required_pcrs.is_empty());
        assert!(!config.allow_debug_mode);
        assert!(config.generate_attestations);
    }

    #[test]
    fn test_mock_attestation_manager() {
        let manager = AttestationManager::mock();
        assert!(!manager.config.enabled);
        assert!(manager.is_debug_mode());
        assert!(manager.nsm_client.is_none());
    }

    #[test]
    fn test_pcr_hex_to_bytes() {
        let mut hex_values = BTreeMap::new();
        hex_values.insert("PCR0".to_string(), "010203".to_string());
        hex_values.insert("PCR1".to_string(), "040506".to_string());

        let byte_values = utils::pcr_hex_to_bytes(&hex_values).unwrap();

        assert_eq!(byte_values.get("PCR0"), Some(&vec![0x01, 0x02, 0x03]));
        assert_eq!(byte_values.get("PCR1"), Some(&vec![0x04, 0x05, 0x06]));
    }

    #[test]
    fn test_parse_build_measurements() {
        let measurements_json = r#"
        {
          "Measurements": {
            "PCR0": "7fb5c55bc2ecbb68ed99a13d7122abfc0666b926a79d5379bc58b9445c84217f59cfdd36c08b2c79552928702efe23e4",
            "PCR1": "235c9e6050abf6b993c915505f3220e2d82b51aff830ad14cbecc2eec1bf0b4ae749d311c663f464cde9f718acca5286"
          }
        }"#;

        let pcrs = utils::parse_build_measurements(measurements_json).unwrap();

        assert_eq!(pcrs.len(), 2);
        assert!(pcrs.contains_key("PCR0"));
        assert!(pcrs.contains_key("PCR1"));
    }

    #[test]
    fn test_validate_pcr_format() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert("PCR0".to_string(), vec![0u8; 48]);
        pcrs.insert("PCR1".to_string(), vec![0u8; 32]);

        let result = utils::validate_pcr_format(&pcrs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("PCR1"));
    }
}
