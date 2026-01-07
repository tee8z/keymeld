use crate::musig::MusigProcessor;
use keymeld_core::{
    identifiers::{SessionId, UserId},
    protocol::{CryptoError, EnclaveError, SessionError},
    SessionSecret,
};
use musig2::PubNonce;
use std::time::SystemTime;
use tracing::info;

use crate::operations::{
    context::EnclaveSharedContext,
    session_context::SigningSessionContext,
    states::{
        signing::{Completed, CoordinatorData},
        SigningStatus,
    },
};
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub struct FinalizingSignature {
    pub session_id: SessionId,
    pub created_at: SystemTime,
    session_secret: SessionSecret,
    coordinator_data: Option<CoordinatorData>,
    musig_processor: MusigProcessor,
}

impl FinalizingSignature {
    pub(crate) fn new(
        session_id: SessionId,
        session_secret: SessionSecret,
        coordinator_data: Option<CoordinatorData>,
        created_at: SystemTime,
        musig_processor: MusigProcessor,
    ) -> Self {
        Self {
            session_id,
            session_secret,
            coordinator_data,
            created_at,
            musig_processor,
        }
    }

    pub fn from_signing_context(
        signing_ctx: &mut SigningSessionContext,
        musig_processor: MusigProcessor,
    ) -> Result<Self, EnclaveError> {
        let session_secret = signing_ctx
            .session_secret
            .clone()
            .ok_or(EnclaveError::Session(
                keymeld_core::protocol::SessionError::SecretNotInitialized,
            ))?;

        Ok(Self::new(
            signing_ctx.session_id.clone(),
            session_secret,
            signing_ctx.coordinator_data.clone(),
            signing_ctx.created_at,
            musig_processor,
        ))
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn session_secret(&self) -> &SessionSecret {
        &self.session_secret
    }

    pub fn coordinator_data(&self) -> &Option<CoordinatorData> {
        &self.coordinator_data
    }

    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }

    pub fn musig_processor(&self) -> &MusigProcessor {
        &self.musig_processor
    }

    pub fn get_participant_count(&self) -> usize {
        self.musig_processor
            .get_session_metadata_public()
            .participant_public_keys
            .len()
    }

    pub fn get_expected_participant_count(&self) -> Option<usize> {
        self.musig_processor
            .get_session_metadata_public()
            .expected_participant_count
    }

    pub fn get_participants(&self) -> Vec<UserId> {
        self.musig_processor
            .get_session_metadata_public()
            .expected_participants
            .clone()
    }

    pub fn get_message(&self) -> Vec<u8> {
        self.musig_processor
            .get_session_metadata_public()
            .message
            .clone()
    }

    pub fn get_current_partial_signature_count(&self) -> usize {
        // Always use the standard partial signature count which handles both regular and adaptor signatures
        self.musig_processor.get_partial_signature_count()
    }

    pub fn get_current_user_partial_signature(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<u8>, EnclaveError> {
        // Get the partial signature bytes from the processor
        self.musig_processor
            .get_user_partial_signature(user_id)
            .map_err(|e| EnclaveError::Musig(e.to_string()))
    }

    pub fn has_all_partial_signatures(&self) -> bool {
        // Check if this session uses adaptor signatures
        let session_metadata = self.musig_processor.get_session_metadata_public();
        let has_adaptor_configs = !session_metadata.adaptor_configs.is_empty();

        if has_adaptor_configs {
            // For adaptor signatures, use the dedicated method
            self.musig_processor.has_all_adaptor_signatures()
        } else {
            // For regular signatures, check if we have enough count
            let signature_count = self.musig_processor.get_partial_signature_count();
            let expected_count = session_metadata.expected_participants.len();
            signature_count >= expected_count
        }
    }

    pub fn finalize_signatures(&mut self) -> Result<Vec<u8>, EnclaveError> {
        let coordinator_user_id = self
            .coordinator_data
            .as_ref()
            .map(|cd| &cd.user_id)
            .ok_or_else(|| {
                EnclaveError::Crypto(CryptoError::Other(
                    "No coordinator data available for finalization".to_string(),
                ))
            })?;

        let signature_bytes = self
            .musig_processor
            .finalize(coordinator_user_id)
            .map_err(|e| {
                EnclaveError::Crypto(CryptoError::Other(format!(
                    "Failed to finalize signature: {}",
                    e
                )))
            })?;

        Ok(signature_bytes.to_vec())
    }

    pub fn get_user_nonce(&self, user_id: &UserId) -> Option<PubNonce> {
        self.musig_processor.get_user_nonce(user_id)
    }

    pub fn get_user_nonce_data(
        &self,
        user_id: &UserId,
    ) -> Option<keymeld_core::protocol::NonceData> {
        self.musig_processor.get_user_nonce_data(user_id)
    }

    pub fn get_nonce_count(&self) -> usize {
        self.musig_processor.get_nonce_count()
    }
}

impl FinalizingSignature {
    /// Finalize the signature.
    /// Returns: Completed
    pub fn finalize(
        self,
        _finalize_cmd: &keymeld_core::protocol::FinalizeSignatureCommand,
        _signing_ctx: &mut SigningSessionContext,
        _enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
    ) -> Result<SigningStatus, EnclaveError> {
        info!(
            "Finalizing signature for signing session {}",
            self.session_id
        );

        // Check if this is a coordinator enclave
        let Some(_coordinator) = self.coordinator_data.clone() else {
            return Err(EnclaveError::Session(SessionError::InvalidId(
                String::from("Only coordinator enclave can finalize signatures"),
            )));
        };

        // Check if we need adaptor signature handling before consuming self
        let use_adaptor = {
            let metadata = self.musig_processor.get_session_metadata_public();
            !metadata.adaptor_configs.is_empty()
        };

        // Finalize the signature (works for both regular and adaptor signatures)
        let mut mutable_self = self;
        let signature_bytes = mutable_self.finalize_signatures().map_err(|e| {
            EnclaveError::Crypto(keymeld_core::protocol::CryptoError::Other(format!(
                "Failed to finalize signature: {}",
                e
            )))
        })?;

        info!(
            "Finalized {} signature for signing session {}: {} bytes",
            if use_adaptor { "adaptor" } else { "regular" },
            mutable_self.session_id,
            signature_bytes.len()
        );

        // Encrypt the finalized signature with session secret
        let encrypted_signature = mutable_self
            .session_secret
            .encrypt_signature(&signature_bytes)
            .map_err(|e| {
                EnclaveError::Crypto(keymeld_core::protocol::CryptoError::Other(format!(
                    "Failed to encrypt finalized signature: {}",
                    e
                )))
            })?;

        // Handle adaptor signatures if present
        let encrypted_adaptor_signatures = if use_adaptor {
            // Get adaptor signature results from metadata (they should be populated during finalization)
            let session_metadata = mutable_self.musig_processor.get_session_metadata_public();
            let adaptor_results = &session_metadata.adaptor_final_signatures;

            if !adaptor_results.is_empty() {
                info!(
                    "Encrypting {} adaptor signature results for session {}",
                    adaptor_results.len(),
                    mutable_self.session_id
                );

                // Serialize adaptor results as BTreeMap<Uuid, AdaptorSignatureResult>
                let adaptor_bytes = serde_json::to_vec(adaptor_results).map_err(|e| {
                    EnclaveError::Crypto(keymeld_core::protocol::CryptoError::Other(format!(
                        "Failed to serialize adaptor signatures: {}",
                        e
                    )))
                })?;

                // Encrypt with session secret
                let encrypted = keymeld_core::crypto::SecureCrypto::encrypt_adaptor_signatures(
                    &adaptor_bytes,
                    &hex::encode(mutable_self.session_secret.as_bytes()),
                )
                .map_err(|e| {
                    EnclaveError::Crypto(keymeld_core::protocol::CryptoError::Other(format!(
                        "Failed to encrypt adaptor signatures: {}",
                        e
                    )))
                })?;

                Some(encrypted)
            } else {
                None
            }
        } else {
            None
        };

        info!(
            "Finalized and encrypted signature for signing session {}",
            mutable_self.session_id
        );

        // Transition to Completed state with encrypted signature
        let expected_count = mutable_self.get_expected_participant_count().unwrap_or(0) as u32;

        let completed = Completed::new(
            mutable_self.session_id,
            mutable_self.session_secret,
            encrypted_signature,
            expected_count,
            mutable_self.created_at,
            mutable_self.coordinator_data,
            mutable_self.musig_processor,
            encrypted_adaptor_signatures,
        );
        Ok(SigningStatus::Completed(completed))
    }
}
