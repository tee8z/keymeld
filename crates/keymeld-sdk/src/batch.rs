//! Client-side batch descriptions and decrypted signature results.
use crate::types::{AdaptorConfig, AdaptorSignatureResult, TaprootTweak};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BatchSigningItem {
    pub(crate) id: Uuid,
    pub(crate) message: [u8; 32],
    pub(crate) mode: BatchSigningMode,
    pub(crate) taproot_tweak: TaprootTweak,
    pub(crate) subset_id: Option<Uuid>,
}

impl BatchSigningItem {
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn message(&self) -> &[u8; 32] {
        &self.message
    }
    pub fn mode(&self) -> &BatchSigningMode {
        &self.mode
    }
    pub fn taproot_tweak(&self) -> &TaprootTweak {
        &self.taproot_tweak
    }
    pub fn subset_id(&self) -> Option<Uuid> {
        self.subset_id
    }

    pub fn new(message: [u8; 32]) -> Self {
        Self {
            id: Uuid::now_v7(),
            message,
            mode: BatchSigningMode::Regular,
            taproot_tweak: TaprootTweak::None,
            subset_id: None,
        }
    }

    pub fn adaptor(message: [u8; 32], configs: Vec<AdaptorConfig>) -> Self {
        Self {
            id: Uuid::now_v7(),
            message,
            mode: BatchSigningMode::Adaptor { configs },
            taproot_tweak: TaprootTweak::None,
            subset_id: None,
        }
    }

    pub fn with_subset(mut self, subset_id: Uuid) -> Self {
        self.subset_id = Some(subset_id);
        self
    }

    pub fn with_tweak(mut self, tweak: TaprootTweak) -> Self {
        self.taproot_tweak = tweak;
        self
    }

    pub fn with_id(mut self, id: Uuid) -> Self {
        self.id = id;
        self
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum BatchSigningMode {
    Regular,
    Adaptor { configs: Vec<AdaptorConfig> },
}

#[derive(Debug, Clone)]
pub struct SignatureResult {
    pub batch_item_id: Uuid,
    pub signature: Option<Vec<u8>>,
    pub adaptor_signatures: Option<BTreeMap<Uuid, AdaptorSignatureResult>>,
    pub error: Option<String>,
}
