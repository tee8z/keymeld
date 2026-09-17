use crate::{
    identifiers::{EnclaveId, SessionId, UserId},
    KeyMeldError,
};
use dashmap::{mapref::entry::Entry, DashMap};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use std::{
    collections::{hash_map::DefaultHasher, BTreeMap},
    hash::{Hash, Hasher},
    sync::atomic::{AtomicU32, Ordering},
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

#[derive(Debug)]
pub struct EnclaveAssignmentManager {
    available_enclaves: Vec<EnclaveId>,
    session_assignments: DashMap<SessionId, SessionAssignment>,
    enclave_loads: DashMap<EnclaveId, AtomicU32>,
}

impl EnclaveAssignmentManager {
    pub fn new(mut available_enclaves: Vec<EnclaveId>) -> Self {
        // Reserved sessions can reconstruct their assignment after restart.
        available_enclaves.sort();
        let enclave_loads = DashMap::new();
        for &enclave_id in &available_enclaves {
            enclave_loads.insert(enclave_id, AtomicU32::new(0));
        }

        Self {
            available_enclaves,
            session_assignments: DashMap::new(),
            enclave_loads,
        }
    }

    pub fn assign_enclaves_for_session_with_distributed_coordinator(
        &self,
        session_id: SessionId,
        user_ids: &[UserId],
        coordinator_user_id: &UserId,
    ) -> Result<SessionAssignment, KeyMeldError> {
        let assignment = self.plan_enclaves_for_session_with_distributed_coordinator(
            session_id,
            user_ids,
            coordinator_user_id,
        )?;
        self.publish_assignment(assignment)
    }

    pub fn plan_enclaves_for_session_with_distributed_coordinator(
        &self,
        session_id: SessionId,
        user_ids: &[UserId],
        coordinator_user_id: &UserId,
    ) -> Result<SessionAssignment, KeyMeldError> {
        if user_ids.is_empty() {
            return Err(KeyMeldError::InvalidConfiguration(
                "Session must have at least one user".to_string(),
            ));
        }

        if self.available_enclaves.is_empty() {
            return Err(KeyMeldError::InvalidConfiguration(
                "No available enclaves".to_string(),
            ));
        }

        if !user_ids.contains(coordinator_user_id) {
            return Err(KeyMeldError::InvalidConfiguration(format!(
                "Coordinator user {coordinator_user_id} not found in expected participants"
            )));
        }

        // Distribute coordinator assignment based on session ID hash
        let session_hash = {
            let mut hasher = DefaultHasher::new();
            session_id.hash(&mut hasher);
            hasher.finish()
        };

        let coordinator_enclave =
            self.available_enclaves[(session_hash as usize) % self.available_enclaves.len()];

        info!(
            "Distributed coordinator assignment: session {} assigned to enclave {} (hash-based distribution)",
            session_id, coordinator_enclave.as_u32()
        );

        // Use existing logic with the distributed coordinator
        self.plan_enclaves_for_session_with_coordinator(
            session_id,
            user_ids,
            coordinator_user_id,
            coordinator_enclave,
        )
    }

    pub fn assign_enclaves_for_session_with_coordinator(
        &self,
        session_id: SessionId,
        user_ids: &[UserId],
        coordinator_user_id: &UserId,
        coordinator_enclave: EnclaveId,
    ) -> Result<SessionAssignment, KeyMeldError> {
        let assignment = self.plan_enclaves_for_session_with_coordinator(
            session_id,
            user_ids,
            coordinator_user_id,
            coordinator_enclave,
        )?;
        self.publish_assignment(assignment)
    }

    pub fn plan_enclaves_for_session_with_coordinator(
        &self,
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

        if user_ids.len() < 2 {
            return Err(KeyMeldError::InvalidConfiguration(
                "MuSig2 requires at least 2 participants. Single-user sessions are not supported."
                    .to_string(),
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

        // Use the configured topology. A single enclave can hold multiple
        // participants; their registration and signing authorities stay separate.
        let remaining_participants: Vec<_> = user_ids
            .iter()
            .filter(|&uid| uid != coordinator_user_id)
            .cloned()
            .collect();

        if user_ids.len() > 1 {
            // Spread keys across multiple enclaves when the deployment has them.
            let mut used_enclaves = std::collections::HashSet::new();
            used_enclaves.insert(coordinator_enclave);

            for (i, user_id) in remaining_participants.iter().enumerate() {
                let enclave_index = i % self.available_enclaves.len();
                let assigned_enclave = self.available_enclaves[enclave_index];
                user_assignments.insert(user_id.clone(), assigned_enclave);
                used_enclaves.insert(assigned_enclave);
            }

            if used_enclaves.len() < 2 && self.available_enclaves.len() > 1 {
                // Force the first non-coordinator participant to a different enclave
                if let Some(first_participant) = remaining_participants.first() {
                    let different_enclave = self
                        .available_enclaves
                        .iter()
                        .find(|&&enclave| enclave != coordinator_enclave)
                        .copied()
                        .ok_or(KeyMeldError::InvalidConfiguration(
                            "Cannot find different enclave for key distribution".to_string(),
                        ))?;

                    user_assignments.insert(first_participant.clone(), different_enclave);
                }
            }
        } else {
            // Single user session is invalid - MuSig2 requires multiple participants
            return Err(KeyMeldError::InvalidConfiguration(
                "MuSig2 requires at least 2 participants. Single-user sessions are not supported."
                    .to_string(),
            ));
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

        // A multi-enclave deployment must still distribute its participants.
        let all_assigned_enclaves = assignment.get_all_assigned_enclaves();
        if all_assigned_enclaves.len() < 2 && self.available_enclaves.len() > 1 {
            return Err(KeyMeldError::InvalidConfiguration(format!(
                "Security violation: All {} participants assigned to single enclave {}. Keys must be distributed across multiple enclaves.",
                user_ids.len(),
                all_assigned_enclaves[0].as_u32()
            )));
        }

        info!(
            "Assigned session {} with specified coordinator: {}, user enclaves: {:?}, distributed across {} enclaves",
            session_id,
            coordinator_enclave.as_u32(),
            assignment
                .user_enclave_assignments
                .values()
                .collect::<Vec<_>>(),
            all_assigned_enclaves.len()
        );

        debug!(
            "Session assignment details for {}: coordinator user {} -> enclave {}, participants: {:?}",
            session_id,
            coordinator_user_id,
            coordinator_enclave.as_u32(),
            assignment.user_enclave_assignments
        );

        Ok(assignment)
    }

    /// Publish only an assignment whose reservation or roster was persisted.
    /// Repeated publication is harmless; a different authority cannot replace it.
    pub fn publish_assignment(
        &self,
        assignment: SessionAssignment,
    ) -> Result<SessionAssignment, KeyMeldError> {
        match self
            .session_assignments
            .entry(assignment.session_id.clone())
        {
            Entry::Occupied(entry) => {
                let current = entry.get();
                if current.coordinator_user_id != assignment.coordinator_user_id
                    || current.coordinator_enclave != assignment.coordinator_enclave
                    || current.user_enclave_assignments != assignment.user_enclave_assignments
                {
                    return Err(KeyMeldError::InvalidConfiguration(
                        "Session assignment differs from its persisted authority".to_string(),
                    ));
                }
                Ok(current.clone())
            }
            Entry::Vacant(entry) => {
                for enclave_id in assignment.user_enclave_assignments.values() {
                    if let Some(load) = self.enclave_loads.get(enclave_id) {
                        load.fetch_add(1, Ordering::Relaxed);
                    }
                }
                entry.insert(assignment.clone());
                Ok(assignment)
            }
        }
    }

    pub fn get_session_assignment(&self, session_id: &SessionId) -> Option<SessionAssignment> {
        self.session_assignments.get(session_id).map(|r| r.clone())
    }

    pub fn copy_session_assignment_for_signing(
        &self,
        keygen_session_id: &SessionId,
        signing_session_id: SessionId,
    ) -> Result<SessionAssignment, KeyMeldError> {
        // Check if already exists first (without holding any locks during the keygen lookup)
        if let Some(existing) = self.session_assignments.get(&signing_session_id) {
            debug!(
                "Signing session {} already has assignment, returning existing",
                signing_session_id
            );
            return Ok(existing.clone());
        }

        // Get keygen assignment BEFORE acquiring the entry lock to avoid deadlock
        // when keygen and signing session IDs hash to the same DashMap shard
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

        // Drop the keygen_assignment reference before acquiring entry lock
        drop(keygen_assignment);

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

        // Now safe to insert - no other DashMap refs held
        match self.session_assignments.entry(signing_session_id) {
            Entry::Occupied(entry) => {
                // Race condition: another thread inserted while we were preparing
                Ok(entry.get().clone())
            }
            Entry::Vacant(entry) => {
                entry.insert(signing_assignment.clone());
                Ok(signing_assignment)
            }
        }
    }

    pub fn remove_session(&self, session_id: &SessionId) -> Option<SessionAssignment> {
        match self.session_assignments.entry(session_id.clone()) {
            Entry::Occupied(entry) => {
                let (_, assignment) = entry.remove_entry();

                if let Some(load) = self.enclave_loads.get(&assignment.coordinator_enclave) {
                    load.fetch_sub(1, Ordering::Relaxed);
                }

                for enclave_id in assignment.user_enclave_assignments.values() {
                    if let Some(load) = self.enclave_loads.get(enclave_id) {
                        load.fetch_sub(1, Ordering::Relaxed);
                    }
                }

                info!("Removed session assignment for {}", session_id);
                Some(assignment)
            }
            Entry::Vacant(_) => None,
        }
    }

    pub fn get_load_distribution(&self) -> BTreeMap<EnclaveId, u32> {
        self.enclave_loads
            .iter()
            .map(|entry| (*entry.key(), entry.value().load(Ordering::Relaxed)))
            .collect()
    }

    pub fn restore_assignment(&self, assignment: SessionAssignment) {
        match self
            .session_assignments
            .entry(assignment.session_id.clone())
        {
            Entry::Occupied(mut entry) => {
                entry.insert(assignment);
            }
            Entry::Vacant(entry) => {
                entry.insert(assignment);
            }
        }
    }

    pub fn get_all_assignments(&self) -> BTreeMap<SessionId, SessionAssignment> {
        self.session_assignments
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    pub fn is_coordinator_for_any_session(&self, enclave_id: &EnclaveId) -> bool {
        self.session_assignments
            .iter()
            .any(|entry| entry.value().coordinator_enclave == *enclave_id)
    }

    pub fn get_coordinator_sessions(&self, enclave_id: &EnclaveId) -> Vec<SessionId> {
        self.session_assignments
            .iter()
            .filter(|entry| entry.value().coordinator_enclave == *enclave_id)
            .map(|entry| entry.value().session_id.clone())
            .collect()
    }

    pub fn get_user_sessions(&self, enclave_id: &EnclaveId) -> Vec<SessionId> {
        self.session_assignments
            .iter()
            .filter(|entry| {
                entry
                    .value()
                    .user_enclave_assignments
                    .values()
                    .any(|&assigned_enclave| assigned_enclave == *enclave_id)
            })
            .map(|entry| entry.value().session_id.clone())
            .collect()
    }

    pub fn restore_session_assignment(&self, assignment: SessionAssignment) {
        match self
            .session_assignments
            .entry(assignment.session_id.clone())
        {
            Entry::Occupied(mut entry) => {
                entry.insert(assignment);
            }
            Entry::Vacant(entry) => {
                entry.insert(assignment);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_enclave_supports_multiple_participants_and_signing_assignment() {
        let enclave = EnclaveId::from(7);
        let manager = EnclaveAssignmentManager::new(vec![enclave]);
        let participants = vec![UserId::new_v7(), UserId::new_v7(), UserId::new_v7()];
        let keygen_id = SessionId::new_v7();
        let assignment = manager
            .assign_enclaves_for_session_with_distributed_coordinator(
                keygen_id.clone(),
                &participants,
                &participants[0],
            )
            .unwrap();
        assert_eq!(assignment.get_all_assigned_enclaves(), vec![enclave]);
        assert_eq!(
            assignment.user_enclave_assignments.len(),
            participants.len()
        );
        for participant in &participants {
            assert_eq!(assignment.get_user_enclave(participant), Some(enclave));
        }
        let signing = manager
            .copy_session_assignment_for_signing(&keygen_id, SessionId::new_v7())
            .unwrap();
        assert_eq!(
            signing.user_enclave_assignments,
            assignment.user_enclave_assignments
        );
    }

    #[test]
    fn multiple_enclaves_keep_two_participants_separate() {
        let enclaves = vec![EnclaveId::from(0), EnclaveId::from(1)];
        let manager = EnclaveAssignmentManager::new(enclaves.clone());
        let participants = vec![UserId::new_v7(), UserId::new_v7()];
        let session_id = SessionId::new_v7();
        let assignment = manager
            .assign_enclaves_for_session_with_coordinator(
                session_id.clone(),
                &participants,
                &participants[0],
                enclaves[0],
            )
            .unwrap();
        assert_eq!(assignment.get_all_assigned_enclaves(), enclaves);
        assert_ne!(
            assignment.get_user_enclave(&participants[0]),
            assignment.get_user_enclave(&participants[1])
        );
    }
}
