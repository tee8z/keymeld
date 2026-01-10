use crate::musig::MusigProcessor;
use keymeld_core::{
    identifiers::{SessionId, UserId},
    protocol::{CryptoError, EnclaveError, SessionError},
    EncryptedData, SessionSecret,
};
use std::{collections::BTreeMap, time::SystemTime};
use tracing::info;
use uuid::Uuid;

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
        // Return participants in BIP327 order (sorted by compressed public key)
        // This matches the order used in KeyAggContext for consistent signer indices
        self.musig_processor
            .get_session_metadata_public()
            .get_all_participant_ids()
    }

    pub fn has_all_batch_signatures(&self) -> bool {
        self.musig_processor.all_batch_signatures_complete()
    }
}

impl FinalizingSignature {
    /// Finalize the signature.
    /// All signing is now batch mode.
    /// Returns: Completed
    pub fn finalize(
        self,
        _finalize_cmd: &keymeld_core::protocol::FinalizeSignatureCommand,
        _signing_ctx: &mut SigningSessionContext,
        _enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
    ) -> Result<SigningStatus, EnclaveError> {
        info!(
            "Finalizing batch signatures for signing session {}",
            self.session_id
        );

        // Check if this is a coordinator enclave
        let Some(_coordinator) = self.coordinator_data.clone() else {
            return Err(EnclaveError::Session(SessionError::InvalidId(
                String::from("Only coordinator enclave can finalize signatures"),
            )));
        };

        // All signing is now batch mode
        self.finalize_batch_signatures()
    }

    /// Finalize batch signatures - each batch item gets its own final signature
    fn finalize_batch_signatures(mut self) -> Result<SigningStatus, EnclaveError> {
        let coordinator_user_id = self
            .coordinator_data
            .as_ref()
            .map(|cd| &cd.user_id)
            .ok_or_else(|| {
                EnclaveError::Crypto(CryptoError::Other(
                    "No coordinator data available for batch finalization".to_string(),
                ))
            })?;

        // Finalize all batch items
        let batch_results = self
            .musig_processor
            .finalize_batch(coordinator_user_id)
            .map_err(|e| {
                EnclaveError::Crypto(CryptoError::Other(format!(
                    "Failed to finalize batch signatures: {}",
                    e
                )))
            })?;

        info!(
            "Finalized {} batch signatures for signing session {}",
            batch_results.len(),
            self.session_id
        );

        // Encrypt each batch result
        let mut encrypted_batch_results: BTreeMap<Uuid, EncryptedData> = BTreeMap::new();
        let mut encrypted_batch_adaptor_results: BTreeMap<Uuid, EncryptedData> = BTreeMap::new();

        for (batch_item_id, finalized_data) in batch_results {
            match finalized_data {
                keymeld_core::protocol::FinalizedData::FinalSignature(sig_bytes) => {
                    let encrypted =
                        self.session_secret
                            .encrypt_signature(&sig_bytes)
                            .map_err(|e| {
                                EnclaveError::Crypto(CryptoError::Other(format!(
                                    "Failed to encrypt batch signature for {}: {}",
                                    batch_item_id, e
                                )))
                            })?;
                    encrypted_batch_results.insert(batch_item_id, encrypted);
                }
                keymeld_core::protocol::FinalizedData::AdaptorSignatures(_adaptor_results) => {
                    // Get the full AdaptorSignatureResult data from the batch item metadata
                    // This contains all the fields needed for signature verification
                    let batch_item = self
                        .musig_processor
                        .get_session_metadata()
                        .batch_items
                        .get(&batch_item_id)
                        .ok_or_else(|| {
                            EnclaveError::Crypto(CryptoError::Other(format!(
                                "Batch item {} not found for adaptor signature",
                                batch_item_id
                            )))
                        })?;

                    // Use the full AdaptorSignatureResult map which contains all required fields
                    let adaptor_bytes = serde_json::to_vec(&batch_item.adaptor_final_signatures)
                        .map_err(|e| {
                            EnclaveError::Crypto(CryptoError::Other(format!(
                                "Failed to serialize batch adaptor signature for {}: {}",
                                batch_item_id, e
                            )))
                        })?;

                    let encrypted = keymeld_core::crypto::SecureCrypto::encrypt_adaptor_signatures(
                        &adaptor_bytes,
                        &hex::encode(self.session_secret.as_bytes()),
                    )
                    .map_err(|e| {
                        EnclaveError::Crypto(CryptoError::Other(format!(
                            "Failed to encrypt batch adaptor signature for {}: {}",
                            batch_item_id, e
                        )))
                    })?;
                    encrypted_batch_adaptor_results.insert(batch_item_id, encrypted);
                }
            }
        }

        info!(
            "Encrypted {} batch signatures and {} batch adaptor signatures for session {}",
            encrypted_batch_results.len(),
            encrypted_batch_adaptor_results.len(),
            self.session_id
        );

        // Transition to Completed state with batch results
        let expected_count = self.get_expected_participant_count().unwrap_or(0) as u32;

        // For batch mode, we use a placeholder for the single signature field
        // The actual signatures are in the batch results
        let placeholder_encrypted = self.session_secret.encrypt_signature(&[]).map_err(|e| {
            EnclaveError::Crypto(CryptoError::Other(format!(
                "Failed to create placeholder encrypted signature: {}",
                e
            )))
        })?;

        let completed = Completed::new(
            self.session_id,
            self.session_secret,
            placeholder_encrypted,
            expected_count,
            self.created_at,
            self.coordinator_data,
            self.musig_processor,
            encrypted_batch_results,
            encrypted_batch_adaptor_results,
        );

        Ok(SigningStatus::Completed(completed))
    }
}
