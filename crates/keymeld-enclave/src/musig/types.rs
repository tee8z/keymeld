use keymeld_core::{
    identifiers::{SessionId, UserId},
    protocol::{SubsetDefinition, TaprootTweak},
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
    /// Per-item taproot tweak for this batch item's KeyAggContext
    pub taproot_tweak: TaprootTweak,
    /// Optional subset_id - if set, use the subset's KeyAggContext for signing
    pub subset_id: Option<Uuid>,
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

    // === Batch signing MuSig2 state ===
    // Single messages are treated as a batch of 1
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
            .field(
                "batch_first_rounds",
                &format!("<{} entries>", self.batch_first_rounds.len()),
            )
            .field(
                "batch_second_rounds",
                &format!("<{} entries>", self.batch_second_rounds.len()),
            )
            .field(
                "batch_adaptor_first_rounds",
                &format!("<{} entries>", self.batch_adaptor_first_rounds.len()),
            )
            .field(
                "batch_adaptor_second_rounds",
                &format!("<{} entries>", self.batch_adaptor_second_rounds.len()),
            )
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct SessionMetadata {
    pub session_id: SessionId,
    pub expected_participants: Vec<UserId>,
    pub participant_public_keys: BTreeMap<UserId, musig2::secp256k1::PublicKey>,
    pub expected_participant_count: Option<usize>,
    pub key_agg_ctx: Option<KeyAggContext>,
    pub phase: SessionPhase,
    /// Session-level taproot tweak (used when batch items don't specify their own)
    pub taproot_tweak: TaprootTweak,
    /// Batch items for signing (single message = batch of 1)
    pub batch_items: BTreeMap<Uuid, BatchItemData>,
    /// Subset definitions for computing additional aggregate keys from participant subsets
    pub subset_definitions: Vec<SubsetDefinition>,
    /// Computed subset KeyAggContexts (subset_id -> KeyAggContext)
    pub subset_key_agg_contexts: BTreeMap<Uuid, KeyAggContext>,
}

impl SessionMetadata {
    /// Get the number of items to sign
    pub fn item_count(&self) -> usize {
        self.batch_items.len()
    }
}
