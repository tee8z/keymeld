use crate::{
    identifiers::{EnclaveId, SessionId, UserId},
    KeyMeldError,
};
use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAssignment {
    pub session_id: SessionId,
    pub coordinator_enclave: EnclaveId,
    pub user_enclave_assignments: BTreeMap<UserId, EnclaveId>,
    pub created_at: u64,
}

impl SessionAssignment {
    pub fn get_user_enclave(&self, user_id: &UserId) -> Option<EnclaveId> {
        self.user_enclave_assignments.get(user_id).copied()
    }

    pub fn get_all_assigned_enclaves(&self) -> Vec<EnclaveId> {
        let mut enclaves = vec![self.coordinator_enclave];
        enclaves.extend(self.user_enclave_assignments.values().copied());
        enclaves.sort();
        enclaves.dedup();
        enclaves
    }
}

#[derive(Debug, Clone)]
pub struct EnclaveAssignmentManager {
    available_enclaves: Vec<EnclaveId>,
    session_assignments: BTreeMap<SessionId, SessionAssignment>,
    enclave_loads: BTreeMap<EnclaveId, u32>,
}

impl EnclaveAssignmentManager {
    pub fn new(available_enclaves: Vec<EnclaveId>) -> Self {
        let mut enclave_loads = BTreeMap::new();
        for &enclave_id in &available_enclaves {
            enclave_loads.insert(enclave_id, 0);
        }

        Self {
            available_enclaves,
            session_assignments: BTreeMap::new(),
            enclave_loads,
        }
    }

    pub fn assign_enclaves_for_session(
        &mut self,
        session_id: SessionId,
        user_ids: &[UserId],
    ) -> Result<SessionAssignment, KeyMeldError> {
        if self.available_enclaves.len() < 2 {
            return Err(KeyMeldError::InvalidConfiguration(
                "Need at least 2 enclaves for coordinator + user separation".to_string(),
            ));
        }

        if user_ids.is_empty() {
            return Err(KeyMeldError::InvalidConfiguration(
                "Session must have at least one user".to_string(),
            ));
        }

        let coordinator_enclave = self.get_least_loaded_enclave();

        let mut user_assignments = BTreeMap::new();
        let available_user_enclaves: Vec<_> = self
            .available_enclaves
            .iter()
            .filter(|&&id| id != coordinator_enclave)
            .copied()
            .collect();

        if available_user_enclaves.is_empty() {
            return Err(KeyMeldError::InvalidConfiguration(
                "No available enclaves for user keys after coordinator assignment".to_string(),
            ));
        }

        for (i, user_id) in user_ids.iter().enumerate() {
            let enclave_index = i % available_user_enclaves.len();
            let assigned_enclave = available_user_enclaves[enclave_index];
            user_assignments.insert(user_id.clone(), assigned_enclave);

            if let Some(load) = self.enclave_loads.get_mut(&assigned_enclave) {
                *load += 1;
            }
        }

        if let Some(load) = self.enclave_loads.get_mut(&coordinator_enclave) {
            *load += 1;
        }

        let assignment = SessionAssignment {
            session_id: session_id.clone(),
            coordinator_enclave,
            user_enclave_assignments: user_assignments,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        info!(
            "Assigned session {} - coordinator: {}, user enclaves: {:?}",
            session_id,
            coordinator_enclave.as_u32(),
            assignment
                .user_enclave_assignments
                .values()
                .collect::<Vec<_>>()
        );

        self.session_assignments
            .insert(session_id, assignment.clone());
        Ok(assignment)
    }

    pub fn assign_enclaves_for_session_with_coordinator(
        &mut self,
        session_id: SessionId,
        user_ids: &[UserId],
        coordinator_enclave: EnclaveId,
    ) -> Result<SessionAssignment, KeyMeldError> {
        if user_ids.is_empty() {
            return Err(KeyMeldError::InvalidConfiguration(
                "Session must have at least one user".to_string(),
            ));
        }

        // Verify coordinator enclave is available
        if !self.available_enclaves.contains(&coordinator_enclave) {
            return Err(KeyMeldError::InvalidConfiguration(format!(
                "Coordinator enclave {} is not available",
                coordinator_enclave.as_u32()
            )));
        }

        let mut user_assignments = BTreeMap::new();
        let available_user_enclaves: Vec<_> = self
            .available_enclaves
            .iter()
            .filter(|&&id| id != coordinator_enclave)
            .copied()
            .collect();

        if available_user_enclaves.is_empty() {
            return Err(KeyMeldError::InvalidConfiguration(
                "No available enclaves for user keys after coordinator assignment".to_string(),
            ));
        }

        for (i, user_id) in user_ids.iter().enumerate() {
            let enclave_index = i % available_user_enclaves.len();
            let assigned_enclave = available_user_enclaves[enclave_index];
            user_assignments.insert(user_id.clone(), assigned_enclave);

            if let Some(load) = self.enclave_loads.get_mut(&assigned_enclave) {
                *load += 1;
            }
        }

        if let Some(load) = self.enclave_loads.get_mut(&coordinator_enclave) {
            *load += 1;
        }

        let assignment = SessionAssignment {
            session_id: session_id.clone(),
            coordinator_enclave,
            user_enclave_assignments: user_assignments,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        info!(
            "Assigned session {} with specified coordinator: {}, user enclaves: {:?}",
            session_id,
            coordinator_enclave.as_u32(),
            assignment
                .user_enclave_assignments
                .values()
                .collect::<Vec<_>>()
        );

        self.session_assignments
            .insert(session_id, assignment.clone());
        Ok(assignment)
    }

    pub fn get_session_assignment(&self, session_id: &SessionId) -> Option<SessionAssignment> {
        self.session_assignments.get(session_id).cloned()
    }

    pub fn copy_session_assignment_for_signing(
        &mut self,
        keygen_session_id: &SessionId,
        signing_session_id: SessionId,
    ) -> Result<SessionAssignment, KeyMeldError> {
        let keygen_assignment =
            self.session_assignments
                .get(keygen_session_id)
                .ok_or_else(|| {
                    KeyMeldError::InvalidConfiguration(format!(
                        "Keygen session assignment not found: {}",
                        keygen_session_id
                    ))
                })?;

        // Create new assignment copying exact enclave assignments from keygen
        let signing_assignment = SessionAssignment {
            session_id: signing_session_id.clone(),
            coordinator_enclave: keygen_assignment.coordinator_enclave,
            user_enclave_assignments: keygen_assignment.user_enclave_assignments.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        info!(
            "Copied session assignment from keygen {} to signing {} - coordinator: {}, user enclaves: {:?}",
            keygen_session_id,
            signing_session_id,
            signing_assignment.coordinator_enclave.as_u32(),
            signing_assignment
                .user_enclave_assignments
                .values()
                .collect::<Vec<_>>()
        );

        self.session_assignments
            .insert(signing_session_id, signing_assignment.clone());
        Ok(signing_assignment)
    }

    pub fn remove_session(&mut self, session_id: &SessionId) -> Option<SessionAssignment> {
        if let Some(assignment) = self.session_assignments.remove(session_id) {
            if let Some(load) = self.enclave_loads.get_mut(&assignment.coordinator_enclave) {
                *load -= 1;
            }

            for enclave_id in assignment.user_enclave_assignments.values() {
                if let Some(load) = self.enclave_loads.get_mut(enclave_id) {
                    *load -= 1;
                }
            }

            debug!("Removed session assignment for {}", session_id);
            Some(assignment)
        } else {
            None
        }
    }

    fn get_least_loaded_enclave(&self) -> EnclaveId {
        self.enclave_loads
            .iter()
            .min_by_key(|(_, &load)| load)
            .map(|(&enclave_id, _)| enclave_id)
            .unwrap_or(self.available_enclaves[0])
    }

    pub fn get_load_distribution(&self) -> &BTreeMap<EnclaveId, u32> {
        &self.enclave_loads
    }

    pub fn restore_assignment(&mut self, assignment: SessionAssignment) {
        self.session_assignments
            .insert(assignment.session_id.clone(), assignment);
    }

    pub fn get_all_assignments(&self) -> &BTreeMap<SessionId, SessionAssignment> {
        &self.session_assignments
    }

    pub fn is_coordinator_for_any_session(&self, enclave_id: &EnclaveId) -> bool {
        self.session_assignments
            .values()
            .any(|assignment| assignment.coordinator_enclave == *enclave_id)
    }

    pub fn get_coordinator_sessions(&self, enclave_id: &EnclaveId) -> Vec<SessionId> {
        self.session_assignments
            .values()
            .filter(|assignment| assignment.coordinator_enclave == *enclave_id)
            .map(|assignment| assignment.session_id.clone())
            .collect()
    }

    pub fn get_user_sessions(&self, enclave_id: &EnclaveId) -> Vec<SessionId> {
        self.session_assignments
            .values()
            .filter(|assignment| {
                assignment
                    .user_enclave_assignments
                    .values()
                    .any(|&assigned_enclave| assigned_enclave == *enclave_id)
            })
            .map(|assignment| assignment.session_id.clone())
            .collect()
    }

    pub fn restore_session_assignment(&mut self, assignment: SessionAssignment) {
        self.session_assignments
            .insert(assignment.session_id.clone(), assignment);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifiers::{SessionId, UserId};

    #[test]
    fn test_session_assignment_creation() {
        let mut manager = EnclaveAssignmentManager::new(vec![
            EnclaveId::from(0),
            EnclaveId::from(1),
            EnclaveId::from(2),
        ]);

        let session_id = SessionId::new_v7();
        let users = vec![UserId::new_v7(), UserId::new_v7()];

        let assignment = manager
            .assign_enclaves_for_session(session_id.clone(), &users)
            .unwrap();

        assert_eq!(assignment.session_id, session_id);
        assert_eq!(assignment.user_enclave_assignments.len(), 2);

        for &user_enclave in assignment.user_enclave_assignments.values() {
            assert_ne!(assignment.coordinator_enclave, user_enclave);
        }
    }

    #[test]
    fn test_load_balancing() {
        let mut manager =
            EnclaveAssignmentManager::new(vec![EnclaveId::from(0), EnclaveId::from(1)]);

        let session1 = SessionId::new_v7();
        let session2 = SessionId::new_v7();

        let assignment1 = manager
            .assign_enclaves_for_session(session1, &[UserId::new_v7()])
            .unwrap();
        let assignment2 = manager
            .assign_enclaves_for_session(session2, &[UserId::new_v7()])
            .unwrap();

        let coordinators = [
            assignment1.coordinator_enclave,
            assignment2.coordinator_enclave,
        ];
        assert!(
            coordinators.contains(&EnclaveId::from(0))
                || coordinators.contains(&EnclaveId::from(1))
        );
    }

    #[test]
    fn test_session_removal() {
        let mut manager = EnclaveAssignmentManager::new(vec![
            EnclaveId::from(0),
            EnclaveId::from(1),
            EnclaveId::from(2),
        ]);

        let session_id = SessionId::new_v7();
        let users = vec![UserId::new_v7()];

        manager
            .assign_enclaves_for_session(session_id.clone(), &users)
            .unwrap();

        assert!(manager.get_session_assignment(&session_id).is_some());

        let removed = manager.remove_session(&session_id);
        assert!(removed.is_some());
        assert!(manager.get_session_assignment(&session_id).is_none());
    }

    #[test]
    fn test_coordinator_specific_assignment() {
        let mut manager = EnclaveAssignmentManager::new(vec![
            EnclaveId::from(0),
            EnclaveId::from(1),
            EnclaveId::from(2),
        ]);

        let session_id = SessionId::new_v7();
        let user_ids = vec![UserId::new_v7(), UserId::new_v7()];
        let specific_coordinator = EnclaveId::from(2);

        let assignment = manager
            .assign_enclaves_for_session_with_coordinator(
                session_id.clone(),
                &user_ids,
                specific_coordinator,
            )
            .unwrap();

        // Verify the specified coordinator was used
        assert_eq!(assignment.coordinator_enclave, specific_coordinator);

        // Verify users were assigned to different enclaves (not the coordinator)
        for user_enclave in assignment.user_enclave_assignments.values() {
            assert_ne!(*user_enclave, specific_coordinator);
        }

        // Verify assignment is stored
        assert!(manager.get_session_assignment(&session_id).is_some());

        // Test invalid coordinator enclave
        let invalid_coordinator = EnclaveId::from(99);
        let result = manager.assign_enclaves_for_session_with_coordinator(
            SessionId::new_v7(),
            &user_ids,
            invalid_coordinator,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_coordinator_user_separation() {
        let mut manager = EnclaveAssignmentManager::new(vec![
            EnclaveId::from(0),
            EnclaveId::from(1),
            EnclaveId::from(2),
        ]);

        let session_id = SessionId::new_v7();
        let users = vec![UserId::new_v7(), UserId::new_v7(), UserId::new_v7()];

        let assignment = manager
            .assign_enclaves_for_session(session_id, &users)
            .unwrap();

        for &user_enclave in assignment.user_enclave_assignments.values() {
            assert_ne!(
                assignment.coordinator_enclave, user_enclave,
                "User enclave should never be the same as coordinator enclave"
            );
        }
    }

    #[test]
    fn test_insufficient_enclaves() {
        let mut manager = EnclaveAssignmentManager::new(vec![EnclaveId::from(0)]);

        let session_id = SessionId::new_v7();
        let users = vec![UserId::new_v7()];

        let result = manager.assign_enclaves_for_session(session_id, &users);
        assert!(result.is_err());
    }
}
