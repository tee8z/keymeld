use aws_nitro_enclaves_cose::crypto::Openssl;
use aws_nitro_enclaves_cose::CoseSign1;
use aws_nitro_enclaves_nsm_api::api::{ErrorCode, Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use keymeld_core::enclave::{AttestationError, CryptoError};
use keymeld_core::AttestationDocument;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;
use std::mem::discriminant;
use thiserror::Error;
use tracing::{debug, error, info};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Error)]
pub enum NsmError {
    #[error("Failed to initialize NSM with fd={0}")]
    InitializationFailed(i32),
    #[error("NSM attestation failed with error code: {0:?}")]
    AttestationFailed(ErrorCode),
    #[error("NSM GetRandom failed with error code: {0:?}")]
    GetRandomFailed(ErrorCode),
    #[error("Requested {requested} random bytes, but got {actual}")]
    RandomBytesLengthMismatch { requested: usize, actual: usize },
    #[error("Failed to parse COSE_Sign1 document: {0}")]
    CoseParseError(String),
    #[error("Failed to get COSE payload: {0}")]
    CosePayloadError(String),
    #[error("Failed to parse attestation payload as CBOR")]
    CborParseError(#[source] serde_cbor::Error),
    #[error("PCR {0} verification failed")]
    PcrVerificationFailed(String),
    #[error("PCR {0} not found in attestation")]
    PcrNotFound(String),
    #[error("Failed to serialize attestation document")]
    SerializationFailed(#[source] serde_cbor::Error),
}

impl From<NsmError> for keymeld_core::enclave::EnclaveError {
    fn from(err: NsmError) -> Self {
        match err {
            NsmError::InitializationFailed(_)
            | NsmError::AttestationFailed(_)
            | NsmError::CoseParseError(_)
            | NsmError::CosePayloadError(_)
            | NsmError::CborParseError(_)
            | NsmError::PcrVerificationFailed(_)
            | NsmError::PcrNotFound(_)
            | NsmError::SerializationFailed(_) => keymeld_core::enclave::EnclaveError::Attestation(
                AttestationError::Other(err.to_string()),
            ),
            NsmError::GetRandomFailed(_) | NsmError::RandomBytesLengthMismatch { .. } => {
                keymeld_core::enclave::EnclaveError::Crypto(CryptoError::Other(err.to_string()))
            }
        }
    }
}

type Result<T> = std::result::Result<T, NsmError>;

pub struct NsmClient {
    nsm_fd: i32,
}

impl NsmClient {
    pub fn new() -> Result<Self> {
        let nsm_fd = nsm_init();
        if nsm_fd < 0 {
            return Err(NsmError::InitializationFailed(nsm_fd));
        }

        debug!("NSM initialized successfully with fd = {}", nsm_fd);

        Ok(Self { nsm_fd })
    }

    pub fn get_attestation_document(
        &self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<AttestationDocument> {
        debug!(
            "Requesting attestation document with user_data len: {:?}, nonce len: {:?}, public_key len: {:?}",
            user_data.map(|d| d.len()),
            nonce.map(|n| n.len()),
            public_key.map(|k| k.len())
        );

        let request = Request::Attestation {
            user_data: user_data.map(|d| ByteBuf::from(d.to_vec())),
            nonce: nonce.map(|n| ByteBuf::from(n.to_vec())),
            public_key: public_key.map(|k| ByteBuf::from(k.to_vec())),
        };

        let response = self.nsm_request(request)?;

        match response {
            Response::Attestation { document } => {
                debug!("Successfully received attestation document");
                self.parse_attestation_document(&document)
            }
            Response::Error(error_code) => {
                error!("NSM returned error: {:?}", error_code);
                Err(NsmError::AttestationFailed(error_code))
            }
            response => {
                error!(
                    "Unexpected NSM response type for attestation: {:?}",
                    response
                );
                // This is truly unexpected and indicates a bug, so use Internal
                Err(NsmError::AttestationFailed(ErrorCode::InvalidOperation))?
            }
        }
    }

    pub fn get_random(&self, num_bytes: u16) -> Result<Vec<u8>> {
        let request = Request::GetRandom;

        let response = self.nsm_request(request)?;

        match response {
            Response::GetRandom { random } => {
                if random.len() != num_bytes as usize {
                    return Err(NsmError::RandomBytesLengthMismatch {
                        requested: num_bytes as usize,
                        actual: random.len(),
                    });
                }
                debug!("Generated {} random bytes", random.len());
                Ok(random)
            }
            Response::Error(error_code) => {
                error!("NSM GetRandom failed: {:?}", error_code);
                Err(NsmError::GetRandomFailed(error_code))
            }
            response => {
                error!("Unexpected NSM response type for GetRandom: {:?}", response);
                Err(NsmError::GetRandomFailed(ErrorCode::InvalidOperation))?
            }
        }
    }

    fn nsm_request(&self, request: Request) -> Result<Response> {
        let response = nsm_process_request(self.nsm_fd, request);
        debug!(
            "NSM request processed, response type: {:?}",
            discriminant(&response)
        );
        Ok(response)
    }

    fn parse_attestation_document(&self, document: &[u8]) -> Result<AttestationDocument> {
        let cose_sign1 =
            CoseSign1::from_bytes(document).map_err(|e| NsmError::CoseParseError(e.to_string()))?;

        let payload = cose_sign1
            .get_payload::<Openssl>(None)
            .map_err(|e| NsmError::CosePayloadError(e.to_string()))?;

        let attestation_data: serde_cbor::Value =
            serde_cbor::from_slice(&payload).map_err(NsmError::CborParseError)?;

        let pcrs = self.extract_pcrs(&attestation_data)?;

        let timestamp = self
            .extract_timestamp(&attestation_data)
            .unwrap_or_else(|| time::OffsetDateTime::now_utc().unix_timestamp() as u64);

        let certificate = self.extract_certificate(&cose_sign1)?;

        let signature = self.extract_signature(&cose_sign1)?;

        let user_data = self.extract_user_data(&attestation_data);
        let public_key = self.extract_public_key(&attestation_data);

        Ok(AttestationDocument {
            pcrs,
            timestamp,
            certificate,
            signature,
            user_data,
            public_key,
        })
    }

    fn extract_pcrs(&self, data: &serde_cbor::Value) -> Result<BTreeMap<String, Vec<u8>>> {
        let mut pcrs = BTreeMap::new();

        if let serde_cbor::Value::Map(map) = data {
            if let Some(serde_cbor::Value::Map(pcr_map)) =
                map.get(&serde_cbor::Value::Text("pcrs".to_string()))
            {
                for (key, value) in pcr_map {
                    if let (
                        serde_cbor::Value::Integer(pcr_num),
                        serde_cbor::Value::Bytes(pcr_value),
                    ) = (key, value)
                    {
                        let pcr_name = format!("PCR{pcr_num}");
                        pcrs.insert(pcr_name, pcr_value.clone());
                        debug!("Extracted PCR{}: {} bytes", pcr_num, pcr_value.len());
                    }
                }
            }
        }

        if pcrs.is_empty() {
            debug!("No PCRs found in attestation document");
        } else {
            info!("Extracted {} PCR values", pcrs.len());
        }

        Ok(pcrs)
    }

    fn extract_user_data(&self, data: &serde_cbor::Value) -> Option<Vec<u8>> {
        if let serde_cbor::Value::Map(map) = data {
            if let Some(serde_cbor::Value::Bytes(user_data)) =
                map.get(&serde_cbor::Value::Text("user_data".to_string()))
            {
                debug!("Extracted user data: {} bytes", user_data.len());
                return Some(user_data.clone());
            }
        }
        None
    }

    fn extract_public_key(&self, data: &serde_cbor::Value) -> Option<Vec<u8>> {
        if let serde_cbor::Value::Map(map) = data {
            if let Some(serde_cbor::Value::Bytes(public_key)) =
                map.get(&serde_cbor::Value::Text("public_key".to_string()))
            {
                debug!("Extracted public key: {} bytes", public_key.len());
                return Some(public_key.clone());
            }
        }
        None
    }

    fn extract_timestamp(&self, data: &serde_cbor::Value) -> Option<u64> {
        if let serde_cbor::Value::Map(map) = data {
            if let Some(serde_cbor::Value::Integer(timestamp)) =
                map.get(&serde_cbor::Value::Text("timestamp".to_string()))
            {
                return Some(*timestamp as u64);
            }
            if let Some(serde_cbor::Value::Integer(timestamp)) =
                map.get(&serde_cbor::Value::Text("iat".to_string()))
            {
                return Some(*timestamp as u64);
            }
        }
        None
    }

    fn extract_certificate(
        &self,
        cose_sign1: &aws_nitro_enclaves_cose::CoseSign1,
    ) -> Result<Vec<u8>> {
        let raw_bytes = match cose_sign1.as_bytes(false) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(Vec::new()),
        };

        if let Ok(serde_cbor::Value::Array(cose_array)) = serde_cbor::from_slice(&raw_bytes) {
            if cose_array.len() >= 4 {
                if let serde_cbor::Value::Bytes(protected_bytes) = &cose_array[0] {
                    if let Ok(serde_cbor::Value::Map(protected_map)) =
                        serde_cbor::from_slice(protected_bytes)
                    {
                        for (key, value) in protected_map {
                            if let serde_cbor::Value::Integer(33) = key {
                                if let serde_cbor::Value::Array(cert_chain) = value {
                                    if let Some(serde_cbor::Value::Bytes(cert)) = cert_chain.first()
                                    {
                                        return Ok(cert.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(Vec::new())
    }

    fn extract_signature(
        &self,
        cose_sign1: &aws_nitro_enclaves_cose::CoseSign1,
    ) -> Result<Vec<u8>> {
        let raw_bytes = match cose_sign1.as_bytes(false) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(Vec::new()),
        };

        if let Ok(serde_cbor::Value::Array(cose_array)) = serde_cbor::from_slice(&raw_bytes) {
            if cose_array.len() >= 4 {
                if let serde_cbor::Value::Bytes(signature_bytes) = &cose_array[3] {
                    return Ok(signature_bytes.clone());
                }
            }
        }

        Ok(Vec::new())
    }

    pub fn verify_measurements(&self, expected_pcrs: &BTreeMap<String, Vec<u8>>) -> Result<()> {
        let attestation = self.get_attestation_document(None, None, None)?;

        for (pcr_name, expected_value) in expected_pcrs {
            match attestation.pcrs.get(pcr_name) {
                Some(actual_value) if actual_value == expected_value => {
                    debug!("PCR {} verification passed", pcr_name);
                }
                Some(actual_value) => {
                    error!(
                        "PCR {} verification failed. Expected: {}, Actual: {}",
                        pcr_name,
                        hex::encode(expected_value),
                        hex::encode(actual_value)
                    );
                    return Err(NsmError::PcrVerificationFailed(pcr_name.clone()));
                }
                None => {
                    error!("PCR {} not found in attestation document", pcr_name);
                    return Err(NsmError::PcrNotFound(pcr_name.clone()));
                }
            }
        }

        info!("All PCR measurements verified successfully");
        Ok(())
    }
}

impl Drop for NsmClient {
    fn drop(&mut self) {
        if self.nsm_fd >= 0 {
            nsm_exit(self.nsm_fd);
            debug!("NSM client closed");
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KeyMeldAttestation {
    pub document: Vec<u8>,
    pub parsed: AttestationDocument,
    pub session_id: String,
    pub generated_at: u64,
}

impl KeyMeldAttestation {
    pub fn generate(
        nsm_client: &NsmClient,
        session_id: &str,
        enclave_public_key: Option<&[u8]>,
    ) -> Result<Self> {
        let session_data = format!("keymeld-session:{session_id}");
        let user_data = session_data.as_bytes();

        let nonce = nsm_client.get_random(32)?;

        let document = nsm_client.get_attestation_document(
            Some(user_data),
            Some(&nonce),
            enclave_public_key,
        )?;

        let raw_document = nsm_client.get_attestation_document(
            Some(user_data),
            Some(&nonce),
            enclave_public_key,
        )?;

        let raw_bytes = serde_cbor::to_vec(&raw_document).map_err(NsmError::SerializationFailed)?;

        Ok(Self {
            document: raw_bytes,
            parsed: document,
            session_id: session_id.to_string(),
            generated_at: time::OffsetDateTime::now_utc().unix_timestamp() as u64,
        })
    }

    pub fn is_valid(&self, max_age_seconds: u64) -> bool {
        let current_time = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
        (current_time - self.generated_at) <= max_age_seconds
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn document_bytes(&self) -> &[u8] {
        &self.document
    }

    pub fn pcr_hex_values(&self) -> BTreeMap<String, String> {
        self.parsed
            .pcrs
            .iter()
            .map(|(k, v)| (k.clone(), hex::encode(v)))
            .collect()
    }
}

pub fn is_debug_mode(nsm_client: &NsmClient) -> Result<bool> {
    let attestation = nsm_client.get_attestation_document(None, None, None)?;

    let all_zeros = attestation
        .pcrs
        .values()
        .all(|pcr| pcr.iter().all(|&byte| byte == 0));

    if all_zeros {
        info!("Running in debug mode - attestation documents will have zero PCRs");
    } else {
        info!("Running in production mode with real PCR measurements");
    }

    Ok(all_zeros)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_document_creation() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert("PCR0".to_string(), vec![0x01; 48]);
        pcrs.insert("PCR1".to_string(), vec![0x02; 48]);

        let doc = AttestationDocument {
            pcrs,
            timestamp: 1234567890,
            certificate: vec![0x03; 64],
            signature: vec![0x04; 64],
            user_data: Some(vec![0x05; 32]),
            public_key: Some(vec![0x06; 33]),
        };

        assert_eq!(doc.pcrs.len(), 2);
        assert!(doc.user_data.is_some());
        assert!(doc.public_key.is_some());
    }

    #[test]
    fn test_keymeld_attestation_validity() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert("PCR0".to_string(), vec![0x01; 48]);

        let doc = AttestationDocument {
            pcrs,
            timestamp: 1234567890,
            certificate: vec![0x03; 64],
            signature: vec![0x04; 64],
            user_data: None,
            public_key: None,
        };

        let attestation = KeyMeldAttestation {
            document: vec![0x07; 100],
            parsed: doc,
            session_id: "test-session".to_string(),
            generated_at: time::OffsetDateTime::now_utc().unix_timestamp() as u64,
        };

        assert!(attestation.is_valid(3600)); // Valid for 1 hour
        assert_eq!(attestation.session_id(), "test-session");
    }
}
