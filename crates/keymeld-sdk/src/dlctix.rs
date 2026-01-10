use crate::error::SdkError;
use crate::managers::{AdaptorConfig, BatchSigningItem, SignatureResult};
use crate::types::{SubsetDefinition, UserId};
pub use dlctix;
use dlctix::musig2::{AdaptorSignature, CompactSignature};
use dlctix::secp::MaybePoint;
use dlctix::{ContractParameters, Outcome, OutcomeIndex, SigningData, WinCondition};
use std::collections::BTreeMap;
use uuid::Uuid;

pub struct DlcSignatureResults {
    pub outcome_signatures: BTreeMap<usize, AdaptorSignature>,
    pub split_signatures: BTreeMap<WinCondition, CompactSignature>,
}

/// Result of building subset definitions for a DLC contract.
pub struct DlcSubsets {
    /// Subset definitions to pass to keygen session creation.
    pub definitions: Vec<SubsetDefinition>,
    /// Mapping from outcome index to subset ID (for use with DlcBatchBuilder).
    pub outcome_subset_ids: BTreeMap<OutcomeIndex, Uuid>,
}

/// Builder for creating keygen subset definitions from DLC contract parameters.
///
/// In a DLC, each outcome's split transactions require signatures from a subset
/// of participants (the winners + market maker). This builder extracts the winner
/// information from the contract parameters and creates the appropriate subset
/// definitions for the keygen session.
pub struct DlcSubsetBuilder<'a> {
    contract_params: &'a ContractParameters,
    market_maker_id: UserId,
    player_ids: Vec<UserId>,
}

impl<'a> DlcSubsetBuilder<'a> {
    /// Create a new subset builder.
    ///
    /// # Arguments
    /// * `contract_params` - The DLC contract parameters containing outcome payouts
    /// * `market_maker_id` - The user ID of the market maker (coordinator)
    /// * `player_ids` - The user IDs of players, indexed to match dlctix player indices
    pub fn new(
        contract_params: &'a ContractParameters,
        market_maker_id: UserId,
        player_ids: Vec<UserId>,
    ) -> Self {
        Self {
            contract_params,
            market_maker_id,
            player_ids,
        }
    }

    /// Build subset definitions for all outcomes.
    ///
    /// Creates one subset per outcome, containing the market maker plus all
    /// winning players for that outcome. Returns both the subset definitions
    /// (for keygen) and the outcome-to-subset-id mapping (for signing).
    pub fn build(self) -> Result<DlcSubsets, SdkError> {
        let mut definitions = Vec::new();
        let mut outcome_subset_ids = BTreeMap::new();

        // Extract winners from each outcome's payout weights
        for (outcome, payout_weights) in &self.contract_params.outcome_payouts {
            // Only process attestation outcomes, not expiry
            let outcome_idx = match outcome {
                Outcome::Attestation(idx) => *idx,
                Outcome::Expiry => continue,
            };

            let subset_id = Uuid::now_v7();
            outcome_subset_ids.insert(outcome_idx, subset_id);

            // Subset includes: market_maker + all players with non-zero payouts
            let mut participants = vec![self.market_maker_id.clone()];

            // PayoutWeights is BTreeMap<usize, u64> - extract player indices with non-zero weights
            for (player_idx, weight) in payout_weights.iter() {
                if *weight > 0 {
                    if *player_idx < self.player_ids.len() {
                        participants.push(self.player_ids[*player_idx].clone());
                    } else {
                        return Err(SdkError::InvalidInput(format!(
                            "Player index {} exceeds player_ids length {}",
                            player_idx,
                            self.player_ids.len()
                        )));
                    }
                }
            }

            definitions.push(SubsetDefinition::with_id(subset_id, participants));
        }

        Ok(DlcSubsets {
            definitions,
            outcome_subset_ids,
        })
    }
}

pub trait AdaptorConfigExt {
    fn from_maybe_point(point: &MaybePoint) -> Result<AdaptorConfig, SdkError>;
}

impl AdaptorConfigExt for AdaptorConfig {
    fn from_maybe_point(point: &MaybePoint) -> Result<AdaptorConfig, SdkError> {
        let point_hex = match point {
            MaybePoint::Infinity => {
                return Err(SdkError::InvalidInput(
                    "Adaptor point is infinity".to_string(),
                ));
            }
            MaybePoint::Valid(p) => hex::encode(p.serialize()),
        };

        Ok(AdaptorConfig::single(point_hex))
    }
}

pub trait SignatureExt {
    fn to_adaptor_signature(&self) -> Result<AdaptorSignature, SdkError>;
    fn to_compact_signature(&self) -> Result<CompactSignature, SdkError>;
}

impl SignatureExt for [u8] {
    fn to_adaptor_signature(&self) -> Result<AdaptorSignature, SdkError> {
        AdaptorSignature::from_bytes(self).map_err(|e| {
            SdkError::InvalidInput(format!("Failed to parse adaptor signature: {:?}", e))
        })
    }

    fn to_compact_signature(&self) -> Result<CompactSignature, SdkError> {
        CompactSignature::from_bytes(self).map_err(|e| {
            SdkError::InvalidInput(format!("Failed to parse compact signature: {:?}", e))
        })
    }
}

impl SignatureExt for Vec<u8> {
    fn to_adaptor_signature(&self) -> Result<AdaptorSignature, SdkError> {
        self.as_slice().to_adaptor_signature()
    }

    fn to_compact_signature(&self) -> Result<CompactSignature, SdkError> {
        self.as_slice().to_compact_signature()
    }
}

pub struct DlcBatchBuilder<'a> {
    signing_data: &'a SigningData,
    outcome_subset_ids: Option<&'a BTreeMap<usize, Uuid>>,
}

impl<'a> DlcBatchBuilder<'a> {
    pub fn new(signing_data: &'a SigningData) -> Self {
        Self {
            signing_data,
            outcome_subset_ids: None,
        }
    }

    pub fn with_outcome_subsets(mut self, subset_ids: &'a BTreeMap<usize, Uuid>) -> Self {
        self.outcome_subset_ids = Some(subset_ids);
        self
    }

    pub fn build(self) -> Result<DlcBatchItems, SdkError> {
        let mut batch_items = Vec::new();
        let mut outcome_batch_ids = BTreeMap::new();
        let mut split_batch_ids = BTreeMap::new();

        // Build outcome transaction items (adaptor signatures, n-of-n)
        for (outcome, sighash) in &self.signing_data.outcome_sighashes {
            let batch_item_id = Uuid::now_v7();

            let message_hash: [u8; 32] = *sighash;

            let item = match outcome {
                Outcome::Attestation(idx) => {
                    outcome_batch_ids.insert(*idx, batch_item_id);

                    if let Some(adaptor_point) = self.signing_data.adaptor_points.get(idx) {
                        let adaptor_config = AdaptorConfig::from_maybe_point(adaptor_point)?;
                        BatchSigningItem::adaptor(message_hash, vec![adaptor_config])
                            .with_id(batch_item_id)
                    } else {
                        BatchSigningItem::new(message_hash).with_id(batch_item_id)
                    }
                }
                Outcome::Expiry => BatchSigningItem::new(message_hash).with_id(batch_item_id),
            };

            batch_items.push(item);
        }

        // Build split transaction items (regular signatures, subset keys)
        for (win_condition, sighash) in &self.signing_data.split_sighashes {
            let batch_item_id = Uuid::now_v7();

            let message_hash: [u8; 32] = *sighash;

            let outcome_idx = match win_condition.outcome {
                Outcome::Attestation(idx) => idx,
                Outcome::Expiry => {
                    return Err(SdkError::InvalidInput(
                        "Expiry outcome not supported for split transactions".to_string(),
                    ));
                }
            };

            let subset_id = self
                .outcome_subset_ids
                .and_then(|ids| ids.get(&outcome_idx).copied());

            split_batch_ids.insert(*win_condition, batch_item_id);

            let mut item = BatchSigningItem::new(message_hash).with_id(batch_item_id);
            if let Some(id) = subset_id {
                item = item.with_subset(id);
            }

            batch_items.push(item);
        }

        Ok(DlcBatchItems {
            items: batch_items,
            outcome_batch_ids,
            split_batch_ids,
        })
    }
}

pub struct DlcBatchItems {
    pub items: Vec<BatchSigningItem>,
    pub outcome_batch_ids: BTreeMap<usize, Uuid>,
    pub split_batch_ids: BTreeMap<WinCondition, Uuid>,
}

impl DlcBatchItems {
    pub fn parse_results(
        &self,
        results: &[SignatureResult],
    ) -> Result<DlcSignatureResults, SdkError> {
        let results_by_id: BTreeMap<Uuid, &SignatureResult> =
            results.iter().map(|r| (r.batch_item_id, r)).collect();

        let mut outcome_signatures = BTreeMap::new();
        for (outcome_idx, batch_id) in &self.outcome_batch_ids {
            let result = results_by_id.get(batch_id).ok_or_else(|| {
                SdkError::Internal(format!("Missing result for outcome {}", outcome_idx))
            })?;

            let adaptor_sigs = result.adaptor_signatures.as_ref().ok_or_else(|| {
                SdkError::Internal(format!("No adaptor signature for outcome {}", outcome_idx))
            })?;

            if adaptor_sigs.is_empty() {
                return Err(SdkError::Internal(format!(
                    "Empty adaptor signatures for outcome {}",
                    outcome_idx
                )));
            }

            // Get the first adaptor signature result from the map
            let first_sig_result = adaptor_sigs.values().next().ok_or_else(|| {
                SdkError::Internal(format!(
                    "No adaptor signature values for outcome {}",
                    outcome_idx
                ))
            })?;

            let adaptor_sig = first_sig_result.signature_scalar.to_adaptor_signature()?;
            outcome_signatures.insert(*outcome_idx, adaptor_sig);
        }

        let mut split_signatures = BTreeMap::new();
        for (win_condition, batch_id) in &self.split_batch_ids {
            let result = results_by_id.get(batch_id).ok_or_else(|| {
                SdkError::Internal(format!("Missing result for split {:?}", win_condition))
            })?;

            let sig_bytes = result.signature.as_ref().ok_or_else(|| {
                SdkError::Internal(format!("No signature for split {:?}", win_condition))
            })?;

            let compact_sig = sig_bytes.to_compact_signature()?;
            split_signatures.insert(*win_condition, compact_sig);
        }

        Ok(DlcSignatureResults {
            outcome_signatures,
            split_signatures,
        })
    }
}
