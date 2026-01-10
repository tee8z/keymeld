use crate::musig::MusigProcessor;
use crate::operations::states::signing::CoordinatorData;
use keymeld_core::{identifiers::SessionId, EncryptedData, SessionSecret};
use std::collections::BTreeMap;
use std::time::SystemTime;
use tracing::info;
use uuid::Uuid;

#[derive(Debug)]
pub struct Completed {
    pub session_id: SessionId,
    pub created_at: SystemTime,
    session_secret: SessionSecret,
    encrypted_signed_message: EncryptedData,
    participant_count: u32,
    encrypted_adaptor_signatures: Option<EncryptedData>,
    coordinator_data: Option<CoordinatorData>,
    musig_processor: MusigProcessor,
    /// Batch mode: encrypted signatures per batch item
    encrypted_batch_signatures: BTreeMap<Uuid, EncryptedData>,
    /// Batch mode: encrypted adaptor signatures per batch item
    encrypted_batch_adaptor_signatures: BTreeMap<Uuid, EncryptedData>,
}

impl Completed {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        session_id: SessionId,
        session_secret: SessionSecret,
        encrypted_signed_message: EncryptedData,
        participant_count: u32,
        created_at: SystemTime,
        coordinator_data: Option<CoordinatorData>,
        musig_processor: MusigProcessor,
        encrypted_batch_signatures: BTreeMap<Uuid, EncryptedData>,
        encrypted_batch_adaptor_signatures: BTreeMap<Uuid, EncryptedData>,
    ) -> Self {
        let completed_at = SystemTime::now();
        let duration = completed_at.duration_since(created_at).unwrap_or_default();

        info!(
            "Batch signing session {} completed successfully in {:.2}s ({} signatures, {} adaptor signatures)",
            session_id,
            duration.as_secs_f64(),
            encrypted_batch_signatures.len(),
            encrypted_batch_adaptor_signatures.len()
        );

        Self {
            session_secret,
            encrypted_signed_message,
            participant_count,
            encrypted_adaptor_signatures: None,
            coordinator_data,
            musig_processor,
            created_at,
            session_id,
            encrypted_batch_signatures,
            encrypted_batch_adaptor_signatures,
        }
    }

    pub fn session_secret(&self) -> &SessionSecret {
        &self.session_secret
    }

    pub fn coordinator_data(&self) -> &Option<CoordinatorData> {
        &self.coordinator_data
    }

    pub fn musig_processor(&self) -> &MusigProcessor {
        &self.musig_processor
    }

    pub fn encrypted_signed_message(&self) -> &EncryptedData {
        &self.encrypted_signed_message
    }

    pub fn participant_count(&self) -> u32 {
        self.participant_count
    }

    pub fn encrypted_adaptor_signatures(&self) -> &Option<EncryptedData> {
        &self.encrypted_adaptor_signatures
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }

    /// Check if this is a batch signing session
    pub fn is_batch(&self) -> bool {
        !self.encrypted_batch_signatures.is_empty()
            || !self.encrypted_batch_adaptor_signatures.is_empty()
    }

    /// Get batch encrypted signatures
    pub fn encrypted_batch_signatures(&self) -> &BTreeMap<Uuid, EncryptedData> {
        &self.encrypted_batch_signatures
    }

    /// Get batch encrypted adaptor signatures
    pub fn encrypted_batch_adaptor_signatures(&self) -> &BTreeMap<Uuid, EncryptedData> {
        &self.encrypted_batch_adaptor_signatures
    }
}
