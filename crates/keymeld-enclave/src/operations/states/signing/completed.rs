use keymeld_core::{musig::MusigProcessor, EncryptedData, SessionId, SessionSecret};
use std::{sync::Arc, time::SystemTime};

use crate::operations::states::signing::CoordinatorData;

#[derive(Debug, Clone)]
pub struct CompletedBuilder {
    pub session_id: SessionId,
    pub session_secret: SessionSecret,
    pub encrypted_signed_message: EncryptedData,
    pub participant_count: u32,
    pub created_at: SystemTime,
    pub coordinator_data: Option<CoordinatorData>,
    pub musig_processor: Arc<MusigProcessor>,
    pub encrypted_adaptor_signatures: Option<EncryptedData>,
}

impl CompletedBuilder {
    pub fn new(
        session_id: SessionId,
        session_secret: SessionSecret,
        encrypted_signed_message: EncryptedData,
        musig_processor: Arc<MusigProcessor>,
    ) -> Self {
        Self {
            session_id,
            session_secret,
            encrypted_signed_message,
            participant_count: 0,
            created_at: SystemTime::now(),
            coordinator_data: None,
            musig_processor,
            encrypted_adaptor_signatures: None,
        }
    }

    pub fn participant_count(mut self, count: u32) -> Self {
        self.participant_count = count;
        self
    }

    pub fn created_at(mut self, time: SystemTime) -> Self {
        self.created_at = time;
        self
    }

    pub fn coordinator_data(mut self, coordinator_data: Option<CoordinatorData>) -> Self {
        self.coordinator_data = coordinator_data;
        self
    }

    pub fn with_adaptor_signatures(mut self, signatures: EncryptedData) -> Self {
        self.encrypted_adaptor_signatures = Some(signatures);
        self
    }

    pub fn build(self) -> Completed {
        Completed {
            session_id: self.session_id,
            session_secret: self.session_secret,
            encrypted_signed_message: self.encrypted_signed_message,
            participant_count: self.participant_count,
            created_at: self.created_at,
            completed_at: SystemTime::now(),
            encrypted_adaptor_signatures: self.encrypted_adaptor_signatures,
            coordinator_data: self.coordinator_data,
            musig_processor: self.musig_processor,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Completed {
    pub session_id: SessionId,
    pub session_secret: SessionSecret,
    pub encrypted_signed_message: EncryptedData,
    pub participant_count: u32,
    pub created_at: SystemTime,
    pub completed_at: SystemTime,
    pub encrypted_adaptor_signatures: Option<EncryptedData>,
    pub coordinator_data: Option<CoordinatorData>,
    pub musig_processor: Arc<MusigProcessor>,
}

impl Completed {
    pub fn builder(
        session_id: SessionId,
        session_secret: SessionSecret,
        encrypted_signed_message: EncryptedData,
        musig_processor: Arc<MusigProcessor>,
    ) -> CompletedBuilder {
        CompletedBuilder::new(
            session_id,
            session_secret,
            encrypted_signed_message,
            musig_processor,
        )
    }

    pub fn new(
        session_id: SessionId,
        session_secret: SessionSecret,
        encrypted_signed_message: EncryptedData,
        musig_processor: Arc<MusigProcessor>,
    ) -> Self {
        CompletedBuilder::new(
            session_id,
            session_secret,
            encrypted_signed_message,
            musig_processor,
        )
        .build()
    }
}
