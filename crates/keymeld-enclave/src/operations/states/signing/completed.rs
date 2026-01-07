use crate::musig::MusigProcessor;
use crate::operations::states::signing::CoordinatorData;
use keymeld_core::{identifiers::SessionId, EncryptedData, SessionSecret};
use std::time::SystemTime;
use tracing::info;

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
        encrypted_adaptor_signatures: Option<EncryptedData>,
    ) -> Self {
        let completed_at = SystemTime::now();
        let duration = completed_at.duration_since(created_at).unwrap_or_default();

        info!(
            "Signing session {} completed successfully in {:.2}s",
            session_id,
            duration.as_secs_f64()
        );

        Self {
            session_secret,
            encrypted_signed_message,
            participant_count,
            encrypted_adaptor_signatures,
            coordinator_data,
            musig_processor,
            created_at,
            session_id,
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
}
