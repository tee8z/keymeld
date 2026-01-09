use crate::{
    enclave::EnclaveManager,
    identifiers::{EnclaveId, UserId},
    session::types::ParticipantData,
    KeyMeldError,
};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn validate_enclave_epochs(
    required_epochs: &BTreeMap<EnclaveId, u64>,
    enclave_manager: &EnclaveManager,
) -> Result<(), KeyMeldError> {
    for (enclave_id, required_epoch) in required_epochs {
        match enclave_manager.get_enclave_key_epoch(enclave_id) {
            Some(current_epoch) if current_epoch == *required_epoch => {
                continue;
            }
            Some(current_epoch) => {
                return Err(KeyMeldError::InvalidState(format!(
                    "Enclave {enclave_id} restarted (epoch {required_epoch} -> {current_epoch}). Ephemeral keys lost. Start new session with fresh keys."
                )));
            }
            None => {
                return Err(KeyMeldError::InvalidState(format!(
                    "Enclave {enclave_id} not found. Enclave may have been removed."
                )));
            }
        }
    }
    Ok(())
}

pub fn merge_participants(
    existing_participants: &mut BTreeMap<UserId, ParticipantData>,
    fresh_participants: BTreeMap<UserId, ParticipantData>,
) -> Result<(), KeyMeldError> {
    for (user_id, fresh_participant) in fresh_participants {
        existing_participants.insert(user_id, fresh_participant);
    }
    Ok(())
}

pub fn validate_all_participants_epochs(
    participants: &BTreeMap<UserId, ParticipantData>,
    enclave_manager: &EnclaveManager,
) -> Result<(), KeyMeldError> {
    for participant in participants.values() {
        participant.validate_epoch(enclave_manager)?;
    }
    Ok(())
}

pub fn is_expired(expires_at: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now > expires_at
}

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Validate that participant ordering matches expected descending order (newest UUIDv7 first).
/// This is critical for MuSig2 as signer indices must be consistent across all operations.
pub fn validate_participant_ordering(
    participants: &BTreeMap<UserId, ParticipantData>,
    expected_order: &[UserId],
) -> Result<(), KeyMeldError> {
    // Extract keys from BTreeMap and sort in descending order
    let mut actual_order: Vec<UserId> = participants.keys().cloned().collect();
    actual_order.sort_by(|a, b| b.cmp(a));

    if actual_order != expected_order {
        return Err(KeyMeldError::InvalidState(format!(
            "Participant ordering mismatch! Expected order does not match actual sorted order. \
             This will cause incorrect signer indices and invalid signatures. \
             Expected: {expected_order:?}, Actual: {actual_order:?}"
        )));
    }

    Ok(())
}

/// Get participants in the correct descending order (newest UUIDv7 first).
/// Use this helper to ensure consistent ordering when extracting from BTreeMap.
pub fn get_participants_in_order(participants: &BTreeMap<UserId, ParticipantData>) -> Vec<UserId> {
    let mut ordered: Vec<UserId> = participants.keys().cloned().collect();
    ordered.sort_by(|a, b| b.cmp(a));
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_expired() {
        let past_timestamp = current_timestamp() - 3600;
        let future_timestamp = current_timestamp() + 3600;

        assert!(is_expired(past_timestamp));
        assert!(!is_expired(future_timestamp));
    }

    #[test]
    fn test_merge_participants() {
        let user1 = UserId::new_v7();
        let user2 = UserId::new_v7();
        let enclave1 = EnclaveId::from(1);

        let mut existing = BTreeMap::new();
        existing.insert(
            user1.clone(),
            ParticipantData {
                user_id: user1.clone(),
                user_key_id: 1,
                enclave_id: enclave1,
                enclave_key_epoch: 1,
                session_encrypted_data: Some("{}".to_string()),
                enclave_encrypted_data: "encrypted_key".to_string(),
                auth_pubkey: vec![1, 2, 3],
                require_signing_approval: false,
            },
        );

        let mut fresh = BTreeMap::new();
        fresh.insert(
            user2.clone(),
            ParticipantData {
                user_id: user2.clone(),
                user_key_id: 2,
                enclave_id: enclave1,
                enclave_key_epoch: 1,
                session_encrypted_data: Some("{}".to_string()),
                enclave_encrypted_data: "encrypted_key".to_string(),
                auth_pubkey: vec![4, 5, 6],
                require_signing_approval: false,
            },
        );

        assert!(merge_participants(&mut existing, fresh).is_ok());
        assert_eq!(existing.len(), 2);
        assert!(existing.contains_key(&user1));
        assert!(existing.contains_key(&user2));
    }
}
