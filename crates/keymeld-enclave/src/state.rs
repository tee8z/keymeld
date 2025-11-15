use anyhow::Result;
use keymeld_core::{
    encrypted_data::*, EncryptedData, PartialSignature, PubNonce, SessionId, SessionSecret, UserId,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub enum EnclaveError {
    OperationNotFound,
    InvalidState,
    CryptoError,
    InvalidInput,
}

#[derive(Debug, Clone)]
pub struct OperationInitData {
    pub session_id: SessionId,
    pub session_secret: Option<SessionSecret>,
    pub message: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub participant_keys: Vec<Vec<u8>>,
    pub aggregate_public_key: Vec<u8>,
    pub is_coordinator: bool,
    pub coordinator_private_key: Option<Vec<u8>>,
    // Structured encrypted data from database (decrypted)
    pub session_encrypted_data: Option<SigningSessionData>,
    pub enclave_encrypted_data: Option<SigningEnclaveData>,
}

#[derive(Debug, Clone)]
pub struct OperationInitialized {
    pub session_id: SessionId,
    pub session_secret: Option<SessionSecret>,
    pub message: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub participant_keys: Vec<Vec<u8>>,
    pub aggregate_public_key: Vec<u8>,
    pub is_coordinator: bool,
    pub coordinator_private_key: Option<Vec<u8>>,
    // Structured encrypted data for future use
    pub session_data: Option<SigningSessionData>,
    pub enclave_data: Option<SigningEnclaveData>,
}

#[derive(Debug, Clone)]
pub struct CollectingNonces {
    pub session_id: SessionId,
    pub session_secret: Option<SessionSecret>,
    pub message: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub participant_keys: Vec<Vec<u8>>,
    pub aggregate_public_key: Vec<u8>,
    pub nonces: BTreeMap<UserId, PubNonce>,
    pub expected_nonce_count: usize,
    pub is_coordinator: bool,
    pub coordinator_private_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct GeneratingSignatures {
    pub session_id: SessionId,
    pub session_secret: Option<SessionSecret>,
    pub message: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub participant_keys: Vec<Vec<u8>>,
    pub aggregate_public_key: Vec<u8>,
    pub aggregate_nonce: Vec<u8>,
    pub partial_signatures: BTreeMap<UserId, PartialSignature>,
    pub expected_signature_count: usize,
    pub is_coordinator: bool,
    pub coordinator_private_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct OperationCompleted {
    pub session_id: SessionId,
    pub session_secret: Option<SessionSecret>,
    pub encrypted_signed_message: Vec<u8>,
    pub participant_count: u32,
}

#[derive(Debug, Clone)]
pub struct OperationFailed {
    pub session_id: SessionId,
    pub error: String,
    pub failed_at: std::time::SystemTime,
}
impl From<OperationInitData> for OperationInitialized {
    fn from(value: OperationInitData) -> Self {
        Self {
            session_id: value.session_id,
            session_secret: value.session_secret,
            message: value.message,
            message_hash: value.message_hash,
            participant_keys: value.participant_keys,
            aggregate_public_key: value.aggregate_public_key,
            is_coordinator: value.is_coordinator,
            coordinator_private_key: value.coordinator_private_key,
            session_data: value.session_encrypted_data,
            enclave_data: value.enclave_encrypted_data,
        }
    }
}

impl OperationInitialized {
    pub fn start_collecting_nonces(
        self,
        first_user: UserId,
        first_nonce: PubNonce,
    ) -> CollectingNonces {
        let expected_count = self.participant_keys.len();
        let mut nonces = BTreeMap::new();
        nonces.insert(first_user, first_nonce);

        CollectingNonces {
            session_id: self.session_id,
            session_secret: self.session_secret,
            message: self.message,
            message_hash: self.message_hash,
            participant_keys: self.participant_keys,
            aggregate_public_key: self.aggregate_public_key,
            nonces,
            expected_nonce_count: expected_count,
            is_coordinator: self.is_coordinator,
            coordinator_private_key: self.coordinator_private_key,
        }
    }

    pub fn encrypt_aggregate_public_key(&self) -> Result<EncryptedData, EnclaveError> {
        self.session_secret
            .as_ref()
            .ok_or(EnclaveError::CryptoError)?
            .encrypt(&self.aggregate_public_key, "aggregate_pubkey")
            .map_err(|_| EnclaveError::CryptoError)
    }

    pub fn get_session_data(&self) -> Option<&SigningSessionData> {
        self.session_data.as_ref()
    }

    pub fn session_secret(&self) -> Option<&SessionSecret> {
        self.session_secret.as_ref()
    }
}

impl CollectingNonces {
    pub fn add_nonce(mut self, user_id: UserId, nonce: PubNonce) -> Result<Self, EnclaveError> {
        if self.nonces.contains_key(&user_id) {
            return Err(EnclaveError::InvalidInput);
        }

        self.nonces.insert(user_id, nonce);
        Ok(self)
    }

    pub fn has_all_nonces(&self) -> bool {
        self.nonces.len() >= self.expected_nonce_count
    }

    pub fn start_generating_signatures(
        self,
        aggregate_nonce: Vec<u8>,
    ) -> Result<GeneratingSignatures, EnclaveError> {
        if !self.has_all_nonces() {
            return Err(EnclaveError::InvalidState);
        }

        Ok(GeneratingSignatures {
            session_id: self.session_id,
            session_secret: self.session_secret,
            message: self.message,
            message_hash: self.message_hash,
            participant_keys: self.participant_keys,
            aggregate_public_key: self.aggregate_public_key,
            aggregate_nonce,
            partial_signatures: BTreeMap::new(),
            expected_signature_count: self.expected_nonce_count,
            is_coordinator: self.is_coordinator,
            coordinator_private_key: self.coordinator_private_key,
        })
    }

    pub fn nonce_count(&self) -> usize {
        self.nonces.len()
    }

    pub fn session_secret(&self) -> Option<&SessionSecret> {
        self.session_secret.as_ref()
    }
}

impl GeneratingSignatures {
    pub fn add_partial_signature(
        mut self,
        user_id: UserId,
        signature: PartialSignature,
    ) -> Result<Self, EnclaveError> {
        if self.partial_signatures.contains_key(&user_id) {
            return Err(EnclaveError::InvalidInput);
        }

        self.partial_signatures.insert(user_id, signature);
        Ok(self)
    }

    pub fn has_all_signatures(&self) -> bool {
        self.partial_signatures.len() >= self.expected_signature_count
    }

    pub fn finalize_operation(
        self,
        final_signature: Vec<u8>,
    ) -> Result<OperationCompleted, EnclaveError> {
        if !self.has_all_signatures() {
            return Err(EnclaveError::InvalidState);
        }

        let encrypted_signed_message = self
            .session_secret
            .as_ref()
            .ok_or(EnclaveError::CryptoError)?
            .encrypt_signature(&final_signature)
            .map_err(|_| EnclaveError::CryptoError)?
            .to_bytes()
            .map_err(|_| EnclaveError::CryptoError)?;

        Ok(OperationCompleted {
            session_id: self.session_id,
            session_secret: self.session_secret,
            encrypted_signed_message,
            participant_count: self.expected_signature_count as u32,
        })
    }

    pub fn signature_count(&self) -> usize {
        self.partial_signatures.len()
    }

    pub fn aggregate_nonce(&self) -> &[u8] {
        &self.aggregate_nonce
    }

    pub fn session_secret(&self) -> Option<&SessionSecret> {
        self.session_secret.as_ref()
    }
}

impl OperationCompleted {
    pub fn encrypted_signed_message(&self) -> &[u8] {
        &self.encrypted_signed_message
    }

    pub fn participant_count(&self) -> u32 {
        self.participant_count
    }

    pub fn session_secret(&self) -> Option<&SessionSecret> {
        self.session_secret.as_ref()
    }
}

impl OperationFailed {
    pub fn new(session_id: SessionId, error: String) -> Self {
        Self {
            session_id,
            error,
            failed_at: std::time::SystemTime::now(),
        }
    }

    pub fn error(&self) -> &str {
        &self.error
    }
}

impl From<OperationInitialized> for OperationFailed {
    fn from(operation: OperationInitialized) -> Self {
        Self::new(
            operation.session_id,
            "Operation failed during initialization".to_string(),
        )
    }
}

impl From<CollectingNonces> for OperationFailed {
    fn from(operation: CollectingNonces) -> Self {
        Self::new(
            operation.session_id,
            "Operation failed during nonce collection".to_string(),
        )
    }
}

impl From<GeneratingSignatures> for OperationFailed {
    fn from(operation: GeneratingSignatures) -> Self {
        Self::new(
            operation.session_id,
            "Operation failed during signature generation".to_string(),
        )
    }
}

#[derive(Debug, Clone)]
pub enum OperationState {
    Initialized(OperationInitialized),
    CollectingNonces(CollectingNonces),
    GeneratingSignatures(GeneratingSignatures),
    Completed(OperationCompleted),
    Failed(OperationFailed),
}

impl OperationState {
    pub fn session_id(&self) -> &SessionId {
        match self {
            OperationState::Initialized(s) => &s.session_id,
            OperationState::CollectingNonces(s) => &s.session_id,
            OperationState::GeneratingSignatures(s) => &s.session_id,
            OperationState::Completed(s) => &s.session_id,
            OperationState::Failed(s) => &s.session_id,
        }
    }

    pub fn state_name(&self) -> &'static str {
        match self {
            OperationState::Initialized(_) => "Initialized",
            OperationState::CollectingNonces(_) => "CollectingNonces",
            OperationState::GeneratingSignatures(_) => "GeneratingSignatures",
            OperationState::Completed(_) => "Completed",
            OperationState::Failed(_) => "Failed",
        }
    }

    pub fn is_complete(&self) -> bool {
        matches!(self, OperationState::Completed(_))
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, OperationState::Failed(_))
    }

    pub fn is_terminal(&self) -> bool {
        self.is_complete() || self.is_failed()
    }

    pub fn get_session_secret(&self) -> Option<&SessionSecret> {
        match self {
            OperationState::Initialized(s) => s.session_secret.as_ref(),
            OperationState::CollectingNonces(s) => s.session_secret.as_ref(),
            OperationState::GeneratingSignatures(s) => s.session_secret.as_ref(),
            OperationState::Completed(s) => s.session_secret.as_ref(),
            OperationState::Failed(_) => None,
        }
    }

    pub fn get_coordinator_private_key(&self) -> Option<Vec<u8>> {
        match self {
            OperationState::Initialized(s) => s.coordinator_private_key.clone(),
            OperationState::CollectingNonces(s) => s.coordinator_private_key.clone(),
            OperationState::GeneratingSignatures(s) => s.coordinator_private_key.clone(),
            _ => None,
        }
    }

    pub fn is_coordinator(&self) -> bool {
        match self {
            OperationState::Initialized(s) => s.is_coordinator,
            OperationState::CollectingNonces(s) => s.is_coordinator,
            OperationState::GeneratingSignatures(s) => s.is_coordinator,
            _ => false,
        }
    }
}

impl From<OperationInitialized> for OperationState {
    fn from(state: OperationInitialized) -> Self {
        OperationState::Initialized(state)
    }
}

impl From<CollectingNonces> for OperationState {
    fn from(state: CollectingNonces) -> Self {
        OperationState::CollectingNonces(state)
    }
}

impl From<GeneratingSignatures> for OperationState {
    fn from(state: GeneratingSignatures) -> Self {
        OperationState::GeneratingSignatures(state)
    }
}

impl From<OperationCompleted> for OperationState {
    fn from(state: OperationCompleted) -> Self {
        OperationState::Completed(state)
    }
}

impl From<OperationFailed> for OperationState {
    fn from(state: OperationFailed) -> Self {
        OperationState::Failed(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keymeld_core::{api::TaprootTweak, musig::MusigProcessor, KeyMaterial};
    use musig2::secp256k1::{PublicKey, SecretKey, SECP256K1};
    use rand::rng;

    fn create_test_key_material() -> (KeyMaterial, PublicKey) {
        let private_key = SecretKey::new(&mut rng());
        let public_key = PublicKey::from_secret_key(SECP256K1, &private_key);
        let key_material = KeyMaterial::new(private_key.secret_bytes().to_vec());
        (key_material, public_key)
    }

    #[test]
    fn test_typestate_transitions() {
        let session_id = SessionId::new_v7();
        let session_secret = Some(SessionSecret::new_random());
        let message = b"test message".to_vec();
        let message_hash = vec![0u8; 32];
        let participant_keys = vec![vec![1u8; 33], vec![2u8; 33]];
        let aggregate_key = vec![3u8; 33];

        let init_data = OperationInitData {
            session_id: session_id.clone(),
            session_secret,
            message,
            message_hash: message_hash.clone(),
            participant_keys,
            aggregate_public_key: aggregate_key,
            is_coordinator: false,
            coordinator_private_key: None,
            session_encrypted_data: Some(SigningSessionData::new()),
            enclave_encrypted_data: Some(SigningEnclaveData::new(
                "test_coordinator_key".to_string(),
                "test_session_secret".to_string(),
            )),
        };
        let initialized: OperationInitialized = init_data.into();

        let mut processor = MusigProcessor::new();
        let user1 = UserId::new_v7();
        let user2 = UserId::new_v7();

        let (key_material1, public_key1) = create_test_key_material();
        let (key_material2, public_key2) = create_test_key_material();

        processor
            .init_session(
                &session_id,
                message_hash.clone(),
                TaprootTweak::None,
                vec![public_key1, public_key2],
                Some(2),
            )
            .unwrap();

        let nonce1 = processor
            .generate_nonce(&session_id, &user1, 0, &key_material1)
            .unwrap();
        let nonce2 = processor
            .generate_nonce(&session_id, &user2, 1, &key_material2)
            .unwrap();

        let collecting = initialized.start_collecting_nonces(user1.clone(), nonce1);

        assert_eq!(collecting.nonce_count(), 1);
        assert!(!collecting.has_all_nonces());

        let collecting = collecting.add_nonce(user2, nonce2).unwrap();

        assert_eq!(collecting.nonce_count(), 2);
        assert!(collecting.has_all_nonces());

        let aggregate_nonce = vec![4u8; 32];
        let generating = collecting
            .start_generating_signatures(aggregate_nonce)
            .unwrap();

        assert_eq!(generating.signature_count(), 0);
        assert!(!generating.has_all_signatures());
    }

    #[test]
    fn test_operation_state_enum() {
        let session_id = SessionId::new_v7();
        let failed = OperationFailed::new(session_id.clone(), "test error".to_string());
        let state = OperationState::from(failed);

        assert_eq!(state.session_id(), &session_id);
        assert_eq!(state.state_name(), "Failed");
        assert!(state.is_failed());
        assert!(state.is_terminal());
        assert!(state.get_session_secret().is_none());
    }
}
