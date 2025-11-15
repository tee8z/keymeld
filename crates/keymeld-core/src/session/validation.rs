use crate::{
    enclave::EnclaveManager,
    identifiers::{EnclaveId, SessionId, UserId},
    session::types::ParticipantData,
    KeyMeldError,
};
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Validates that all enclave epochs in the required set match current enclave epochs
pub fn validate_enclave_epochs(
    required_epochs: &BTreeMap<EnclaveId, u64>,
    enclave_manager: &EnclaveManager,
) -> Result<(), KeyMeldError> {
    for (enclave_id, required_epoch) in required_epochs {
        match enclave_manager.get_enclave_key_epoch(enclave_id) {
            Some(current_epoch) if current_epoch == *required_epoch => {
                // Epoch matches, this enclave is still valid
                continue;
            }
            Some(current_epoch) => {
                return Err(KeyMeldError::InvalidState(format!(
                    "Enclave {} restarted (epoch {} -> {}). Ephemeral keys lost. Start new session with fresh keys.",
                    enclave_id, required_epoch, current_epoch
                )));
            }
            None => {
                return Err(KeyMeldError::InvalidState(format!(
                    "Enclave {} not found. Enclave may have been removed.",
                    enclave_id
                )));
            }
        }
    }
    Ok(())
}

/// Merges fresh participant data into existing participant map
pub fn merge_participants(
    existing_participants: &mut BTreeMap<UserId, ParticipantData>,
    fresh_participants: BTreeMap<UserId, ParticipantData>,
) -> Result<(), KeyMeldError> {
    for (user_id, fresh_participant) in fresh_participants {
        existing_participants.insert(user_id, fresh_participant);
    }
    Ok(())
}

/// Validates that all participants in a session have valid epochs
pub fn validate_all_participants_epochs(
    participants: &BTreeMap<UserId, ParticipantData>,
    enclave_manager: &EnclaveManager,
) -> Result<(), KeyMeldError> {
    for participant in participants.values() {
        participant.validate_epoch(enclave_manager)?;
    }
    Ok(())
}

/// Checks if a timestamp has expired
pub fn is_expired(expires_at: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now > expires_at
}

/// Creates an expiration timestamp from now + duration
pub fn create_expiration(duration: Duration) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now + duration.as_secs()
}

/// Gets current timestamp in seconds since epoch
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Validates that expected participants match registered participants
pub fn validate_participant_completeness(
    expected_participants: &[UserId],
    registered_participants: &BTreeMap<UserId, ParticipantData>,
) -> Result<(), KeyMeldError> {
    let expected_count = expected_participants.len();
    let registered_count = registered_participants.len();

    if registered_count < expected_count {
        return Err(KeyMeldError::ValidationError(format!(
            "Insufficient participants: expected {}, got {}",
            expected_count, registered_count
        )));
    }

    // Verify all expected participants are registered
    for expected_user in expected_participants {
        if !registered_participants.contains_key(expected_user) {
            return Err(KeyMeldError::ValidationError(format!(
                "Expected participant {} not registered",
                expected_user
            )));
        }
    }

    Ok(())
}

/// Extracts user IDs from participant data
pub fn extract_user_ids(participants: &BTreeMap<UserId, ParticipantData>) -> Vec<UserId> {
    participants.keys().cloned().collect()
}

/// Extracts enclave IDs from participant data
pub fn extract_enclave_ids(participants: &BTreeMap<UserId, ParticipantData>) -> Vec<EnclaveId> {
    participants
        .values()
        .map(|p| p.enclave_id)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Creates a map of enclave epochs from participants
pub fn create_enclave_epochs_map(
    participants: &BTreeMap<UserId, ParticipantData>,
) -> BTreeMap<EnclaveId, u64> {
    let mut epochs = BTreeMap::new();
    for participant in participants.values() {
        epochs.insert(participant.enclave_id, participant.enclave_key_epoch);
    }
    epochs
}

/// Validates session ID format and length
pub fn validate_session_id(session_id: &SessionId) -> Result<(), KeyMeldError> {
    if session_id.to_string().is_empty() {
        return Err(KeyMeldError::ValidationError(
            "Session ID cannot be empty".to_string(),
        ));
    }
    // Add more validation as needed
    Ok(())
}

/// Validates user ID format and length
pub fn validate_user_id(user_id: &UserId) -> Result<(), KeyMeldError> {
    if user_id.to_string().is_empty() {
        return Err(KeyMeldError::ValidationError(
            "User ID cannot be empty".to_string(),
        ));
    }
    // Add more validation as needed
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifiers::{EnclaveId, SessionId, UserId};

    use std::time::Duration;

    fn create_test_participant(user_id: UserId, enclave_id: EnclaveId) -> ParticipantData {
        ParticipantData::new_with_epoch(
            user_id,
            enclave_id,
            1,
            "{}".to_string(),            // session_encrypted_data
            "encrypted_key".to_string(), // enclave_encrypted_data
        )
    }

    #[test]
    fn test_is_expired() {
        let past_timestamp = current_timestamp() - 3600; // 1 hour ago
        let future_timestamp = current_timestamp() + 3600; // 1 hour from now

        assert!(is_expired(past_timestamp));
        assert!(!is_expired(future_timestamp));
    }

    #[test]
    fn test_create_expiration() {
        let duration = Duration::from_secs(3600);
        let expiration = create_expiration(duration);
        let expected = current_timestamp() + 3600;

        // Allow for small timing differences
        assert!((expiration as i64 - expected as i64).abs() < 2);
    }

    #[test]
    fn test_validate_participant_completeness() {
        let user1 = UserId::new_v7();
        let user2 = UserId::new_v7();
        let enclave1 = EnclaveId::from(1);

        let expected_participants = vec![user1.clone(), user2.clone()];
        let mut registered_participants = BTreeMap::new();
        registered_participants.insert(user1.clone(), create_test_participant(user1, enclave1));

        // Should fail with insufficient participants
        assert!(validate_participant_completeness(
            &expected_participants,
            &registered_participants
        )
        .is_err());

        // Add second participant
        registered_participants.insert(user2.clone(), create_test_participant(user2, enclave1));

        // Should now succeed
        assert!(validate_participant_completeness(
            &expected_participants,
            &registered_participants
        )
        .is_ok());
    }

    #[test]
    fn test_extract_user_ids() {
        let user1 = UserId::new_v7();
        let user2 = UserId::new_v7();
        let enclave1 = EnclaveId::from(1);

        let mut participants = BTreeMap::new();
        participants.insert(
            user1.clone(),
            create_test_participant(user1.clone(), enclave1),
        );
        participants.insert(
            user2.clone(),
            create_test_participant(user2.clone(), enclave1),
        );

        let user_ids = extract_user_ids(&participants);
        assert_eq!(user_ids.len(), 2);
        assert!(user_ids.contains(&user1));
        assert!(user_ids.contains(&user2));
    }

    #[test]
    fn test_extract_enclave_ids() {
        let user1 = UserId::new_v7();
        let user2 = UserId::new_v7();
        let enclave1 = EnclaveId::from(1);
        let enclave2 = EnclaveId::from(2);

        let mut participants = BTreeMap::new();
        participants.insert(user1.clone(), create_test_participant(user1, enclave1));
        participants.insert(user2.clone(), create_test_participant(user2, enclave2));

        let enclave_ids = extract_enclave_ids(&participants);
        assert_eq!(enclave_ids.len(), 2);
        assert!(enclave_ids.contains(&enclave1));
        assert!(enclave_ids.contains(&enclave2));
    }

    #[test]
    fn test_create_enclave_epochs_map() {
        let user1 = UserId::new_v7();
        let user2 = UserId::new_v7();
        let enclave1 = EnclaveId::from(1);
        let enclave2 = EnclaveId::from(2);

        let mut participants = BTreeMap::new();
        participants.insert(user1.clone(), create_test_participant(user1, enclave1));
        participants.insert(user2.clone(), create_test_participant(user2, enclave2));

        let epochs_map = create_enclave_epochs_map(&participants);
        assert_eq!(epochs_map.len(), 2);
        assert_eq!(epochs_map.get(&enclave1), Some(&1));
        assert_eq!(epochs_map.get(&enclave2), Some(&1));
    }

    #[test]
    fn test_validate_session_id() {
        let valid_session_id = SessionId::new_v7();
        assert!(validate_session_id(&valid_session_id).is_ok());
    }

    #[test]
    fn test_validate_user_id() {
        let valid_user_id = UserId::new_v7();
        assert!(validate_user_id(&valid_user_id).is_ok());
    }

    #[test]
    fn test_merge_participants() {
        let user1 = UserId::new_v7();
        let user2 = UserId::new_v7();
        let enclave1 = EnclaveId::from(1);

        let mut existing = BTreeMap::new();
        existing.insert(
            user1.clone(),
            create_test_participant(user1.clone(), enclave1),
        );

        let mut fresh = BTreeMap::new();
        fresh.insert(
            user2.clone(),
            create_test_participant(user2.clone(), enclave1),
        );

        assert!(merge_participants(&mut existing, fresh).is_ok());
        assert_eq!(existing.len(), 2);
        assert!(existing.contains_key(&user1));
        assert!(existing.contains_key(&user2));
    }
}
