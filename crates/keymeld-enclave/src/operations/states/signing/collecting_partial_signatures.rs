use crate::musig::signatures::BatchPartialSigData;
use crate::musig::MusigProcessor;
use keymeld_core::{
    identifiers::{SessionId, UserId},
    protocol::{EnclaveError, InternalError, SignatureData, ValidationError},
    SessionSecret,
};
use std::collections::BTreeMap;
use std::time::SystemTime;
use tracing::info;
use uuid::Uuid;

use crate::operations::{
    context::EnclaveSharedContext,
    session_context::SigningSessionContext,
    states::{signing::CoordinatorData, SigningStatus},
    FinalizingSignature,
};
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub struct CollectingPartialSignatures {
    pub session_id: SessionId,
    pub created_at: SystemTime,
    session_secret: SessionSecret,
    coordinator_data: Option<CoordinatorData>,
    musig_processor: MusigProcessor,
}

impl CollectingPartialSignatures {
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

    pub fn get_participants(&self) -> Vec<UserId> {
        // Return participants in BIP327 order (sorted by compressed public key)
        // This matches the order used in KeyAggContext for consistent signer indices
        self.musig_processor
            .get_session_metadata_public()
            .get_all_participant_ids()
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

    pub fn can_aggregate_signatures(&self) -> Result<bool, EnclaveError> {
        // Check if all batch signatures have been collected
        Ok(self.musig_processor.all_batch_signatures_complete())
    }

    pub fn has_all_batch_signatures(&self) -> bool {
        self.musig_processor.all_batch_signatures_complete()
    }
}

impl CollectingPartialSignatures {
    /// Process FinalizeSignature command - collect partial signatures.
    /// All signing is now batch mode.
    /// Returns: FinalizingSignature | CollectingPartialSignatures (if still waiting)
    pub fn collect_partial_signatures(
        mut self,
        finalize_cmd: &keymeld_core::protocol::FinalizeSignatureCommand,
        signing_ctx: &mut SigningSessionContext,
        enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
    ) -> Result<SigningStatus, EnclaveError> {
        info!(
            "Processing batch partial signature collection for signing session {}",
            self.session_id
        );

        let encrypted_partial_signatures = &finalize_cmd.partial_signatures;

        // Get session secret for decryption
        let session_secret = signing_ctx.session_secret.as_ref().ok_or_else(|| {
            EnclaveError::Internal(InternalError::Other(
                "Session secret not available for decryption".to_string(),
            ))
        })?;

        let expected_participants = self.get_participants();
        let mut added_count = 0;

        // Process all incoming encrypted partial signatures
        for (user_id, encrypted_signature_hex) in encrypted_partial_signatures {
            // Decrypt the signature data
            let encrypted_signature = keymeld_core::crypto::EncryptedData::from_hex(
                encrypted_signature_hex,
            )
            .map_err(|e| {
                EnclaveError::Internal(InternalError::Other(format!(
                    "Failed to decode encrypted signature hex for user {}: {}",
                    user_id, e
                )))
            })?;

            let signature_data: keymeld_core::protocol::SignatureData = session_secret
                .decrypt_value(&encrypted_signature, "signature_data")
                .map_err(|e| {
                    EnclaveError::Internal(InternalError::Other(format!(
                        "Failed to decrypt signature data for user {}: {}",
                        user_id, e
                    )))
                })?;

            // Validate user is expected participant
            let signer_index = expected_participants
                .iter()
                .position(|id| id == user_id)
                .ok_or(EnclaveError::Validation(ValidationError::Other(format!(
                    "User {} not found in expected participants",
                    user_id
                ))))?;

            // All signatures now come as batch signatures
            match signature_data {
                SignatureData::Regular(_partial_sig) => {
                    return Err(EnclaveError::Validation(ValidationError::Other(
                        "Expected batch signatures, got regular signature. Use batch mode."
                            .to_string(),
                    )));
                }
                SignatureData::Adaptor(_adaptor_sigs) => {
                    return Err(EnclaveError::Validation(ValidationError::Other(
                        "Expected batch signatures, got adaptor signatures. Use batch mode."
                            .to_string(),
                    )));
                }
                SignatureData::Batch(batch_sigs) => {
                    // Convert batch signatures to the format expected by the processor
                    let batch_sigs_data: BTreeMap<Uuid, BatchPartialSigData> = batch_sigs
                        .into_iter()
                        .map(|(batch_item_id, sig_data)| {
                            let sig = match *sig_data {
                                SignatureData::Regular(partial_sig) => {
                                    BatchPartialSigData::Regular {
                                        signature: partial_sig.serialize().to_vec(),
                                        nonce: Vec::new(), // Nonce not needed for receiving signatures
                                    }
                                }
                                SignatureData::Adaptor(adaptor_sigs) => {
                                    BatchPartialSigData::Adaptor(
                                        adaptor_sigs
                                            .into_iter()
                                            .map(|(adaptor_id, partial_sig)| {
                                                (
                                                    adaptor_id,
                                                    partial_sig.serialize().to_vec(),
                                                    Vec::new(), // Nonce not needed
                                                )
                                            })
                                            .collect(),
                                    )
                                }
                                SignatureData::Batch(_) => {
                                    // Nested batch not supported
                                    BatchPartialSigData::Regular {
                                        signature: Vec::new(),
                                        nonce: Vec::new(),
                                    }
                                }
                            };
                            (batch_item_id, sig)
                        })
                        .collect();

                    self.musig_processor
                        .add_batch_partial_signatures(user_id, batch_sigs_data)
                        .map_err(|e| {
                            EnclaveError::Internal(InternalError::Other(format!(
                                "Failed to add batch partial signatures for user {}: {:?}",
                                user_id, e
                            )))
                        })?;
                    info!(
                        "Added batch partial signatures for user {} at index {}",
                        user_id, signer_index
                    );
                }
            }

            info!(
                "Added partial signature for user {} in signing session {}",
                user_id, self.session_id
            );

            added_count += 1;
        }

        info!(
            "Processed {} batch partial signatures for signing session {}",
            added_count, self.session_id
        );

        // Check if we have enough signatures to finalize and transition to FinalizingSignature
        if self.can_finalize_signature() {
            info!(
                "All batch partial signatures collected for signing session {}, transitioning to FinalizingSignature",
                self.session_id
            );

            // Only coordinator enclave should finalize
            if let Some(_coordinator_data) = &self.coordinator_data {
                let finalizing_signature = FinalizingSignature::try_from(self)?;
                // Auto-chain to finalize and transition to Completed
                finalizing_signature.finalize(finalize_cmd, signing_ctx, enclave_ctx)
            } else {
                info!(
                    "Non-coordinator enclave completed batch partial signature collection for session {}",
                    self.session_id
                );
                Ok(SigningStatus::CollectingPartialSignatures(self))
            }
        } else {
            let batch_item_count = self
                .musig_processor
                .get_session_metadata_public()
                .batch_items
                .len();
            let expected_count = self.get_expected_participant_count().unwrap_or(0);
            info!(
                "Signing session {} still collecting batch partial signatures: batch_items={}, expected_participants={}",
                self.session_id, batch_item_count, expected_count
            );
            Ok(SigningStatus::CollectingPartialSignatures(self))
        }
    }
}

impl CollectingPartialSignatures {
    /// Check if we can finalize the signature (all batch partial signatures collected)
    fn can_finalize_signature(&self) -> bool {
        self.musig_processor.all_batch_signatures_complete()
    }
}

impl TryFrom<CollectingPartialSignatures>
    for crate::operations::states::signing::FinalizingSignature
{
    type Error = EnclaveError;

    fn try_from(value: CollectingPartialSignatures) -> Result<Self, Self::Error> {
        value.musig_processor.get_aggregate_pubkey().map_err(|e| {
            EnclaveError::Session(keymeld_core::protocol::SessionError::MusigInitialization(
                format!(
                    "Cannot finalize signature, aggregate pubkey not ready: {}",
                    e
                ),
            ))
        })?;

        Ok(FinalizingSignature::new(
            value.session_id,
            value.session_secret,
            value.coordinator_data,
            value.created_at,
            value.musig_processor,
        ))
    }
}
