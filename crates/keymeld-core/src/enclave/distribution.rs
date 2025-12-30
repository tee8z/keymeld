use crate::{
    identifiers::{EnclaveId, SessionId, UserId},
    KeyMeldError,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAssignment {
    pub session_id: SessionId,
    pub coordinator_user_id: UserId,
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

    pub fn assign_enclaves_for_session_with_coordinator(
        &mut self,
        session_id: SessionId,
        user_ids: &[UserId],
        coordinator_user_id: &UserId,
        coordinator_enclave: EnclaveId,
    ) -> Result<SessionAssignment, KeyMeldError> {
        if user_ids.is_empty() {
            return Err(KeyMeldError::InvalidConfiguration(
                "Session must have at least one user".to_string(),
            ));
        }

        if !self.available_enclaves.contains(&coordinator_enclave) {
            return Err(KeyMeldError::InvalidConfiguration(format!(
                "Coordinator enclave {} is not available",
                coordinator_enclave.as_u32()
            )));
        }

        if !user_ids.contains(coordinator_user_id) {
            return Err(KeyMeldError::InvalidConfiguration(format!(
                "Coordinator user {coordinator_user_id} not found in expected participants"
            )));
        }

        let mut user_assignments = BTreeMap::new();

        user_assignments.insert(coordinator_user_id.clone(), coordinator_enclave);

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

        let remaining_participants: Vec<_> = user_ids
            .iter()
            .filter(|&uid| uid != coordinator_user_id)
            .cloned()
            .collect();

        for (i, user_id) in remaining_participants.iter().enumerate() {
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
            coordinator_user_id: (*coordinator_user_id).clone(),
            coordinator_enclave,
            user_enclave_assignments: user_assignments,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
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

        debug!(
            "Session assignment details for {}: coordinator user {} -> enclave {}, participants: {:?}",
            session_id,
            coordinator_user_id,
            coordinator_enclave.as_u32(),
            assignment.user_enclave_assignments
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
        let keygen_assignment = self.session_assignments.get(keygen_session_id).ok_or(
            KeyMeldError::InvalidConfiguration(format!(
                "Keygen session assignment not found: {keygen_session_id}"
            )),
        )?;

        let signing_assignment = SessionAssignment {
            session_id: signing_session_id.clone(),
            coordinator_user_id: keygen_assignment.coordinator_user_id.clone(),
            coordinator_enclave: keygen_assignment.coordinator_enclave,
            user_enclave_assignments: keygen_assignment.user_enclave_assignments.clone(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
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

            info!("Removed session assignment for {}", session_id);
            Some(assignment)
        } else {
            None
        }
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
