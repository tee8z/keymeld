use keymeld_core::{
    identifiers::{SessionId, UserId},
    protocol::TaprootTweak,
    KeyMaterial,
};
use musig2::KeyAggContext;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

pub use keymeld_core::protocol::{AdaptorConfig, AdaptorHint, AdaptorSignatureResult, AdaptorType};

/// Metadata for a single batch item in a batch signing session
#[derive(Debug, Clone)]
pub struct BatchItemData {
    pub batch_item_id: Uuid,
    pub message: Vec<u8>,
    pub adaptor_configs: Vec<AdaptorConfig>,
    pub adaptor_final_signatures: BTreeMap<Uuid, AdaptorSignatureResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionPhase {
    CollectingParticipants,
    NonceGeneration,
    NonceAggregation,
    Signing,
    Aggregation,
    AdaptorNonceGeneration,
    AdaptorNonceAggregation,
    Complete,
    Failed,
}

pub struct UserMusigSession {
    pub user_id: UserId,
    pub coordinator: bool,
    pub signer_index: usize,
    pub private_key: Option<KeyMaterial>,
    /// Auth public key for verifying signing approval signatures
    pub auth_pubkey: Option<Vec<u8>>,
    /// Whether this user requires explicit approval before signing
    pub require_signing_approval: bool,

    // === Single message MuSig2 state (backward compat) ===
    pub first_round: Option<musig2::FirstRound>,
    pub second_round: Option<musig2::SecondRound<Vec<u8>>>,
    pub adaptor_first_rounds: BTreeMap<Uuid, musig2::FirstRound>,
    pub adaptor_second_rounds: BTreeMap<Uuid, musig2::SecondRound<Vec<u8>>>,

    // === Batch signing MuSig2 state ===
    /// First rounds per batch item (batch_item_id -> FirstRound)
    pub batch_first_rounds: BTreeMap<Uuid, musig2::FirstRound>,
    /// Second rounds per batch item (batch_item_id -> SecondRound)
    pub batch_second_rounds: BTreeMap<Uuid, musig2::SecondRound<Vec<u8>>>,
    /// Adaptor first rounds per batch item (batch_item_id -> (adaptor_id -> FirstRound))
    pub batch_adaptor_first_rounds: BTreeMap<Uuid, BTreeMap<Uuid, musig2::FirstRound>>,
    /// Adaptor second rounds per batch item (batch_item_id -> (adaptor_id -> SecondRound))
    pub batch_adaptor_second_rounds: BTreeMap<Uuid, BTreeMap<Uuid, musig2::SecondRound<Vec<u8>>>>,
}

impl std::fmt::Debug for UserMusigSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserMusigSession")
            .field("user_id", &self.user_id)
            .field("signer_index", &self.signer_index)
            .field("private_key", &"<redacted>")
            .field("first_round", &"<opaque>")
            .field("second_round", &"<opaque>")
            .field(
                "adaptor_first_rounds",
                &format!("<{} entries>", self.adaptor_first_rounds.len()),
            )
            .field(
                "adaptor_second_rounds",
                &format!("<{} entries>", self.adaptor_second_rounds.len()),
            )
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct SessionMetadata {
    pub session_id: SessionId,
    /// Single message (backward compat, used if batch_items is empty)
    pub message: Vec<u8>,
    pub expected_participants: Vec<UserId>,
    pub participant_public_keys: BTreeMap<UserId, musig2::secp256k1::PublicKey>,
    pub expected_participant_count: Option<usize>,
    pub key_agg_ctx: Option<KeyAggContext>,
    pub phase: SessionPhase,
    pub taproot_tweak: TaprootTweak,
    /// Single message adaptor configs (backward compat)
    pub adaptor_configs: Vec<AdaptorConfig>,
    pub adaptor_final_signatures: BTreeMap<Uuid, AdaptorSignatureResult>,
    /// Batch items for batch signing (takes precedence if non-empty)
    pub batch_items: BTreeMap<Uuid, BatchItemData>,
}

impl SessionMetadata {
    /// Check if this is a batch signing session
    pub fn is_batch(&self) -> bool {
        !self.batch_items.is_empty()
    }

    /// Get the number of items to sign (1 for single, N for batch)
    pub fn item_count(&self) -> usize {
        if self.is_batch() {
            self.batch_items.len()
        } else {
            1
        }
    }
}
