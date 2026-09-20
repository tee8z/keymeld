//! Exact participant scope derived from an already verified native roster.
use crate::{BatchSigningItem, BatchSigningMode, SdkError};
use keymeld_core::{
    authorization::SignedRoster,
    escrow::{AdaptorContext, KeyTweak, PublicKeyBytes, ScopeSigner, SigningItem, SigningScope},
    protocol::{AdaptorType, TaprootTweak},
    UserId,
};
use sha2::{Digest, Sha256};

fn invalid(message: &str) -> SdkError {
    SdkError::InvalidInput(message.into())
}
fn tweak(value: &TaprootTweak) -> KeyTweak {
    match value {
        TaprootTweak::None => KeyTweak::None,
        TaprootTweak::UnspendableTaproot => KeyTweak::TaprootKeyPath,
        TaprootTweak::TaprootWithMerkleRoot { merkle_root } => KeyTweak::TaprootMerkleRoot {
            merkle_root: *merkle_root,
        },
        TaprootTweak::PlainTweak { tweak } => KeyTweak::PlainScalar { scalar: *tweak },
        TaprootTweak::XOnlyTweak { tweak } => KeyTweak::XOnlyScalar { scalar: *tweak },
    }
}

/// The caller must authenticate the roster against the pinned enclave and manifest.
/// Application verifiers must independently check that these messages implement
/// the participant's consent; this function only computes the native signing scope.
pub fn scope_for_participant(
    roster: &SignedRoster,
    items: &[BatchSigningItem],
    participant: &UserId,
) -> Result<SigningScope, SdkError> {
    let roster = &roster.roster;
    if !roster.participants.contains_key(participant) {
        return Err(invalid("Scope participant is absent from the roster"));
    }
    let mut batch = Vec::new();
    for item in items {
        let users: Vec<_> = match item.subset_id() {
            Some(id) => roster
                .subset_definitions
                .iter()
                .find(|subset| subset.subset_id == id)
                .ok_or_else(|| invalid("Scope references an unauthorized subset"))?
                .participants
                .iter()
                .collect(),
            None => roster.participants.keys().collect(),
        };
        if item.subset_id().is_some() && tweak(item.taproot_tweak()) != tweak(&roster.taproot_tweak)
        {
            return Err(invalid(
                "Subset item tweak differs from the keygen session tweak",
            ));
        }
        if !users.contains(&participant) {
            continue;
        }
        let mut signers = users
            .into_iter()
            .map(|user| {
                Ok(ScopeSigner {
                    user_id: user.clone(),
                    public_key: PublicKeyBytes::new(
                        roster
                            .participants
                            .get(user)
                            .ok_or_else(|| invalid("Scope signer is absent from the roster"))?,
                    )?,
                })
            })
            .collect::<Result<Vec<_>, SdkError>>()?;
        signers.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        let adaptor = match item.mode() {
            BatchSigningMode::Regular => AdaptorContext::None,
            BatchSigningMode::Adaptor { configs } => {
                if configs.len() != 1
                    || configs[0].adaptor_type != AdaptorType::Single
                    || configs[0].adaptor_points.len() != 1
                    || configs[0].hints.is_some()
                {
                    return Err(invalid(
                        "Escrow requires exactly one adaptor point and no hints",
                    ));
                }
                AdaptorContext::Single {
                    adaptor_id: configs[0].adaptor_id,
                    point: PublicKeyBytes::new(
                        &hex::decode(&configs[0].adaptor_points[0])
                            .map_err(|_| invalid("Invalid adaptor point"))?,
                    )?,
                }
            }
        };
        let item_tweak = if item.subset_id().is_some() {
            tweak(&roster.taproot_tweak)
        } else {
            tweak(item.taproot_tweak())
        };
        batch.push(SigningItem {
            item_id: item.id(),
            message_digest: Sha256::digest(item.message()).into(),
            subset_id: item.subset_id(),
            signers,
            tweak: item_tweak,
            adaptor,
        });
    }
    if batch.is_empty() {
        return Err(invalid("Participant signs no messages in the batch"));
    }
    Ok(SigningScope {
        session_tweak: tweak(&roster.taproot_tweak),
        batch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use keymeld_core::{authorization::ParticipantRoster, protocol::SubsetDefinition, SessionId};
    use std::collections::BTreeMap;
    use uuid::Uuid;
    fn fixture() -> (SignedRoster, UserId, Uuid) {
        let participant = UserId::new_v7();
        let key = secp256k1::SecretKey::from_byte_array([11; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1)
            .serialize()
            .to_vec();
        let subset = Uuid::now_v7();
        (
            SignedRoster {
                enclave_public_key: key.clone(),
                roster: ParticipantRoster {
                    keygen_session_id: SessionId::new_v7(),
                    manifest_hash: vec![1; 32],
                    participants: BTreeMap::from([(participant.clone(), key.clone())]),
                    registrations: BTreeMap::new(),
                    aggregate_public_key: key.clone(),
                    subset_aggregate_keys: BTreeMap::from([(subset, key)]),
                    subset_definitions: vec![SubsetDefinition {
                        subset_id: subset,
                        participants: vec![participant.clone()],
                    }],
                    taproot_tweak: TaprootTweak::None,
                },
                signature: Vec::new(),
            },
            participant,
            subset,
        )
    }
    #[test]
    fn a_subset_tweak_cannot_be_silently_replaced_with_the_keygen_tweak() {
        let (roster, user, subset) = fixture();
        let item = BatchSigningItem::new([42; 32])
            .with_subset(subset)
            .with_tweak(TaprootTweak::PlainTweak { tweak: [3; 32] });
        assert!(scope_for_participant(&roster, &[item], &user).is_err());
        let item = BatchSigningItem::new([42; 32]).with_subset(subset);
        let scope = scope_for_participant(&roster, &[item], &user).unwrap();
        assert_eq!(scope.batch[0].tweak, KeyTweak::None);
    }
    #[test]
    fn a_full_group_item_preserves_its_explicit_effective_tweak() {
        let (roster, user, _) = fixture();
        let item =
            BatchSigningItem::new([42; 32]).with_tweak(TaprootTweak::PlainTweak { tweak: [3; 32] });
        let scope = scope_for_participant(&roster, &[item], &user).unwrap();
        assert_eq!(
            scope.batch[0].tweak,
            KeyTweak::PlainScalar { scalar: [3; 32] }
        );
    }
}
