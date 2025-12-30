use crate::identifiers::{SessionId, UserId};
use musig2::{AggNonce, KeyAggContext, PartialSignature};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::api::TaprootTweak;
use crate::KeyMaterial;

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub enum AdaptorHint {
    Scalar(Vec<u8>),
    Point(Vec<u8>),
    Hash(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AdaptorConfig {
    pub adaptor_id: Uuid,
    pub adaptor_type: AdaptorType,
    pub adaptor_points: Vec<String>,
    pub hints: Option<Vec<AdaptorHint>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
pub enum AdaptorType {
    Single,
    And,
    Or,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AdaptorSignatureResult {
    pub adaptor_id: Uuid,
    pub adaptor_type: AdaptorType,
    pub signature_scalar: Vec<u8>,
    pub nonce_point: Vec<u8>,
    pub adaptor_points: Vec<Vec<u8>>,
    pub hints: Option<Vec<AdaptorHint>>,
    pub aggregate_adaptor_point: Vec<u8>,
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
    pub signer_index: usize,
    pub private_key: Option<KeyMaterial>,
    // Per-user MuSig2 state machines (cannot be shared across users)
    pub first_round: Option<musig2::FirstRound>,
    pub second_round: Option<musig2::SecondRound<Vec<u8>>>,
    pub adaptor_first_rounds: BTreeMap<Uuid, musig2::FirstRound>,
    pub adaptor_second_rounds: BTreeMap<Uuid, musig2::SecondRound<Vec<u8>>>,
}

impl std::fmt::Debug for UserMusigSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserMusigSession")
            .field("user_id", &self.user_id)
            .field("signer_index", &self.signer_index)
            .field("private_key", &self.private_key)
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
    pub message: Vec<u8>,
    pub expected_participants: Vec<UserId>,
    pub participant_public_keys: BTreeMap<UserId, musig2::secp256k1::PublicKey>,
    pub expected_participant_count: Option<usize>,
    pub key_agg_ctx: Option<KeyAggContext>,
    pub nonces: BTreeMap<UserId, musig2::PubNonce>,
    pub phase: SessionPhase,
    pub taproot_tweak: TaprootTweak,
    pub adaptor_configs: Vec<AdaptorConfig>,
    pub adaptor_aggregate_nonces: BTreeMap<Uuid, AggNonce>,
    pub adaptor_partial_signatures: BTreeMap<Uuid, BTreeMap<UserId, PartialSignature>>,
    pub adaptor_final_signatures: BTreeMap<Uuid, AdaptorSignatureResult>,
    pub regular_signature: Option<String>,
}
