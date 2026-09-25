//! Client orchestration of native MuSig2 rounds over the confidential relay.
//!
//! Journals contain private application protocol state. Persist them in trusted,
//! authenticated application storage, never in a gateway-visible plaintext row.
//! A checkpoint must complete before a command can cause an enclave side effect.

use crate::{
    confidential::{ConfidentialTransport, PinnedEnclave, PreparedConfidentialCommand},
    AuthorizationCredentials, BatchSigningItem, BatchSigningMode, KeyMeldClient, SdkError,
    SessionCredentials,
};
use keymeld_core::{
    authorization::{
        authorization_digest, EnclaveRecipientAuthorization, ParticipantApproval, SignedRoster,
        SignedSessionManifest, SigningAuthorization, ROSTER_CONTEXT, SUBSET_AGGREGATE_CONTEXT,
    },
    protocol::{
        AddParticipantsBatchCommand, AggregatePublicKeyResponse, Command, DistributeNoncesCommand,
        DistributeParticipantPublicKeysBatchCommand, EnclaveBatchItem, EnclaveBatchResult,
        EnclaveCommand, EnclaveOutcome, EnclavePublicKeyInfo, FinalizeSignatureCommand,
        GetAggregatePublicKeyCommand, InitKeygenSessionCommand, InitSigningSessionCommand,
        KeygenCommand, KeygenOutcome, MusigCommand, MusigOutcome, Outcome,
        ParticipantRegistrationData, SigningCommand, SigningOutcome, SystemCommand, SystemOutcome,
        ValidateRegistrationCommand,
    },
    EnclaveId, SessionId, UserId,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
};
use uuid::Uuid;

const MAX_JOURNAL_COMMANDS: usize = 4096;

#[cfg(not(target_arch = "wasm32"))]
pub type CheckpointFuture<'a> = Pin<Box<dyn Future<Output = Result<(), SdkError>> + Send + 'a>>;
#[cfg(target_arch = "wasm32")]
pub type CheckpointFuture<'a> = Pin<Box<dyn Future<Output = Result<(), SdkError>> + 'a>>;

/// Implement using durable authenticated storage. Returning success before the
/// write is durable can make a crash retry generate a different signing round.
pub trait ConfidentialCheckpoint: Send + Sync {
    fn save<'a>(&'a self, journal: &'a ConfidentialJournal) -> CheckpointFuture<'a>;
}

#[derive(Clone, Serialize, Deserialize)]
struct JournalEntry {
    input_commitment: [u8; 32],
    request: PreparedConfidentialCommand,
    outcome: Option<Outcome>,
}

#[derive(Clone, Serialize, Deserialize)]
struct SavedBatch {
    input_commitment: [u8; 32],
    items: Vec<EnclaveBatchItem>,
}

/// Serialize only to the authorized application's authenticated storage.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ConfidentialJournal {
    commands: BTreeMap<String, JournalEntry>,
    signing_batches: BTreeMap<SessionId, SavedBatch>,
    opaque_route_id: Option<Uuid>,
    aborted_signing_sessions: BTreeSet<SessionId>,
}

impl ConfidentialJournal {
    pub fn recorded_command(&self, stage: &str, enclave: EnclaveId) -> Option<&Command> {
        self.commands
            .get(&format!("{stage}/{}", enclave.as_u32()))
            .map(|entry| &entry.request.request().command)
    }
    pub fn command_outcome(&self, stage: &str, enclave: EnclaveId) -> Option<&Outcome> {
        self.commands
            .get(&format!("{stage}/{}", enclave.as_u32()))
            .and_then(|entry| entry.outcome.as_ref())
    }
    pub fn command_was_rejected(&self, stage: &str, enclave: EnclaveId) -> bool {
        self.command_outcome(stage, enclave)
            .is_some_and(|outcome| matches!(outcome.response, EnclaveOutcome::Error(_)))
    }
    pub fn is_signing_aborted(&self, session: &SessionId) -> bool {
        self.aborted_signing_sessions.contains(session)
    }
}

impl std::fmt::Debug for ConfidentialJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfidentialJournal")
            .field("commands", &self.commands.len())
            .field("signing_batches", &self.signing_batches.len())
            .finish_non_exhaustive()
    }
}

fn invalid(message: impl Into<String>) -> SdkError {
    SdkError::InvalidInput(message.into())
}

/// Holds attested recipients and a journal of exact requests. The caller owns
/// session creation and storage; the gateway receives no manifest or roster.
pub struct ConfidentialSession<'a> {
    transport: ConfidentialTransport<'a>,
    manifest: &'a SignedSessionManifest,
    recipients: &'a EnclaveRecipientAuthorization,
    credentials: &'a SessionCredentials,
    authority: &'a AuthorizationCredentials,
    reply_key: &'a AuthorizationCredentials,
    enclaves: BTreeMap<EnclaveId, PinnedEnclave>,
    journal: &'a mut ConfidentialJournal,
    checkpoint: &'a dyn ConfidentialCheckpoint,
}

impl<'a> ConfidentialSession<'a> {
    pub fn recorded_command(&self, stage: &str, enclave: EnclaveId) -> Option<&Command> {
        self.journal.recorded_command(stage, enclave)
    }
    pub fn command_outcome(&self, stage: &str, enclave: EnclaveId) -> Option<&Outcome> {
        self.journal.command_outcome(stage, enclave)
    }
    pub fn command_was_rejected(&self, stage: &str, enclave: EnclaveId) -> bool {
        self.journal.command_was_rejected(stage, enclave)
    }
    pub fn is_signing_aborted(&self, session: &SessionId) -> bool {
        self.journal.is_signing_aborted(session)
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        client: &'a KeyMeldClient,
        manifest: &'a SignedSessionManifest,
        recipients: &'a EnclaveRecipientAuthorization,
        expected_epochs: &BTreeMap<EnclaveId, u64>,
        credentials: &'a SessionCredentials,
        authority: &'a AuthorizationCredentials,
        reply_key: &'a AuthorizationCredentials,
        journal: &'a mut ConfidentialJournal,
        checkpoint: &'a dyn ConfidentialCheckpoint,
    ) -> Result<Self, SdkError> {
        manifest.verify()?;
        recipients.verify(manifest)?;
        let public = authority.public_key_bytes();
        if public != manifest.manifest.creator_pubkey
            || public != manifest.manifest.signing_pubkey
            || credentials.public_key_bytes() != manifest.manifest.session_public_key
            || expected_epochs.keys().collect::<BTreeSet<_>>()
                != recipients.recipient_public_keys.keys().collect()
        {
            return Err(invalid(
                "Confidential session credentials or recipient epochs differ",
            ));
        }
        let transport = ConfidentialTransport::new(client);
        let mut enclaves = BTreeMap::new();
        for (id, expected_key) in &recipients.recipient_public_keys {
            let enclave = transport.attest(*id).await?;
            if enclave.public_key() != expected_key.as_slice()
                || expected_epochs.get(id) != Some(&enclave.key_epoch())
            {
                return Err(invalid("Confidential enclave key or epoch changed"));
            }
            enclaves.insert(*id, enclave);
        }
        Ok(Self {
            transport,
            manifest,
            recipients,
            credentials,
            authority,
            reply_key,
            enclaves,
            journal,
            checkpoint,
        })
    }

    /// Checkpoint the exact encrypted request before transmission. Input is a
    /// semantic commitment before randomized inner encryption is constructed.
    pub async fn command_once<T: Serialize, F>(
        &mut self,
        stage: &str,
        enclave_id: EnclaveId,
        input: &T,
        build: F,
    ) -> Result<EnclaveOutcome, SdkError>
    where
        F: FnOnce() -> Result<EnclaveCommand, SdkError>,
    {
        if stage.is_empty() || stage.len() > 256 {
            return Err(invalid("Invalid confidential journal stage"));
        }
        let key = format!("{stage}/{}", enclave_id.as_u32());
        let commitment = self.stage_commitment(stage, enclave_id, input)?;
        let enclave = self
            .enclaves
            .get(&enclave_id)
            .ok_or_else(|| invalid("Unapproved confidential recipient"))?;
        if let Some(saved) = self.journal.commands.get(&key) {
            if saved.input_commitment != commitment {
                return Err(invalid("Confidential retry changed its original inputs"));
            }
        } else {
            if self.journal.commands.len() >= MAX_JOURNAL_COMMANDS {
                return Err(invalid("Confidential journal command limit reached"));
            }
            let route_id = *self
                .journal
                .opaque_route_id
                .get_or_insert_with(Uuid::now_v7);
            let request = self.transport.prepare(
                enclave,
                route_id,
                Command::new(build()?),
                self.authority,
                self.reply_key,
            )?;
            self.journal.commands.insert(
                key.clone(),
                JournalEntry {
                    input_commitment: commitment,
                    request,
                    outcome: None,
                },
            );
        }
        // Also retry a previously failed storage write before any transmission.
        self.checkpoint.save(self.journal).await?;
        let saved = self
            .journal
            .commands
            .get(&key)
            .expect("inserted journal entry");
        let outcome = match &saved.outcome {
            Some(outcome) => outcome.clone(),
            None => {
                self.transport
                    .execute(enclave, &saved.request, self.reply_key)
                    .await?
            }
        };
        self.journal
            .commands
            .get_mut(&key)
            .expect("inserted journal entry")
            .outcome = Some(outcome.clone());
        self.checkpoint.save(self.journal).await?;
        match outcome.response {
            EnclaveOutcome::Error(keymeld_core::protocol::ErrorResponse {
                error: keymeld_core::protocol::EnclaveError::EscrowPreparationExhausted { reason },
            }) => Err(SdkError::EscrowPreparationExhausted { reason }),
            EnclaveOutcome::Error(error) => Err(invalid(format!(
                "Enclave rejected the confidential operation: {}",
                error.error
            ))),
            response => Ok(response),
        }
    }

    /// What a journaled stage commits to: its inputs, before randomized encryption.
    fn stage_commitment<T: Serialize>(
        &self,
        stage: &str,
        enclave_id: EnclaveId,
        input: &T,
    ) -> Result<[u8; 32], SdkError> {
        Ok(authorization_digest(
            "confidential-client-stage-v1",
            &(
                self.manifest.digest()?,
                self.recipients,
                enclave_id,
                stage,
                input,
            ),
        )?)
    }

    /// Retry only a definitively rejected, authenticated enclave command.
    /// A pending request may already have executed and must retain its identity.
    /// After this durable reset, the builder must allocate a new inner request
    /// ID as well as the new native command ID while retaining the action attempt.
    pub async fn clear_rejected_command(
        &mut self,
        stage: &str,
        enclave_id: EnclaveId,
    ) -> Result<(), SdkError> {
        let key = format!("{stage}/{}", enclave_id.as_u32());
        let entry = self
            .journal
            .commands
            .get(&key)
            .ok_or_else(|| invalid("No rejected command exists for this stage"))?;
        if !entry
            .outcome
            .as_ref()
            .is_some_and(|outcome| matches!(outcome.response, EnclaveOutcome::Error(_)))
        {
            return Err(invalid("Only a definitive enclave rejection can be reset; pending or successful commands retain their identity"));
        }
        let saved = self.journal.commands.remove(&key).expect("checked entry");
        if let Err(error) = self.checkpoint.save(self.journal).await {
            self.journal.commands.insert(key, saved);
            return Err(error);
        }
        Ok(())
    }

    /// Validate a deposited registration privately before accepting an entry.
    pub async fn validate_registration(
        &mut self,
        participant: &ParticipantRegistrationData,
    ) -> Result<(), SdkError> {
        participant
            .registration_authorization
            .verify(self.manifest, &participant.enclave_encrypted_data)?;
        let enclave = self.registration_enclave(participant)?;
        let manifest = self.manifest.clone();
        let registration = participant.clone();
        let response = self
            .command_once(
                &format!("admit/{}", participant.user_id),
                enclave,
                participant,
                move || {
                    Ok(EnclaveCommand::System(SystemCommand::ValidateRegistration(
                        ValidateRegistrationCommand {
                            authorization_manifest: Box::new(manifest),
                            participant: registration,
                        },
                    )))
                },
            )
            .await?;
        let EnclaveOutcome::System(SystemOutcome::RegistrationValidated(validated)) = response
        else {
            return Err(invalid("Unexpected confidential registration response"));
        };
        if validated.public_key != participant.registration_authorization.context.public_key
            || validated.auth_pubkey != participant.auth_pubkey
        {
            return Err(invalid(
                "Enclave registration result differs from participant consent",
            ));
        }
        Ok(())
    }

    fn registration_enclave(
        &self,
        registration: &ParticipantRegistrationData,
    ) -> Result<EnclaveId, SdkError> {
        let context = &registration.registration_authorization.context;
        let assigned = self
            .recipients
            .user_enclave_assignments
            .get(&registration.user_id)
            .ok_or_else(|| invalid("Registration is outside the approved participant roster"))?;
        let enclave = self
            .enclaves
            .get(assigned)
            .ok_or_else(|| invalid("Missing attested registration recipient"))?;
        if context.user_id != registration.user_id
            || context.enclave_id != *assigned
            || context.enclave_key_epoch != enclave.key_epoch()
            || context.auth_pubkey != registration.auth_pubkey
            || context.require_signing_approval != registration.require_signing_approval
        {
            return Err(invalid(
                "Registration changed its assigned enclave or approval policy",
            ));
        }
        Ok(*assigned)
    }

    /// Restore key custody after enclave restart using the original encrypted
    /// keygen requests. Never reconstruct interrupted secret-nonce rounds.
    pub async fn restore_keygen(
        &mut self,
        registrations: &BTreeMap<UserId, ParticipantRegistrationData>,
    ) -> Result<SignedRoster, SdkError> {
        let route_id = *self
            .journal
            .opaque_route_id
            .get_or_insert_with(Uuid::now_v7);
        let all = self.enclaves.keys().copied().collect::<Vec<_>>();
        let missing = self.missing_keygen_sessions(route_id, &all).await?;
        // Restoring a restart replays journaled keygen commands, so it is only
        // possible once complete_keygen has recorded them. A session with no
        // journaled keygen stage is a first run instead: fall through and let
        // complete_keygen establish it. A partially journaled session still
        // fails below, where the specific missing stage is detected.
        let restorable = self
            .journal
            .commands
            .keys()
            .any(|key| key.starts_with("keygen/"));
        if !missing.is_empty() && restorable {
            let coordinator = self.recipients.user_enclave_assignments
                [&self.manifest.manifest.coordinator_user_id];
            for session in self.journal.signing_batches.keys() {
                let final_key = format!("sign/{session}/final/{}", coordinator.as_u32());
                let completed = self.journal.commands.get(&final_key).is_some_and(|entry| {
                    entry.outcome.as_ref().is_some_and(|outcome| {
                        matches!(
                            &outcome.response,
                            EnclaveOutcome::Musig(MusigOutcome::Signing(
                                SigningOutcome::FinalSignature(_)
                            ))
                        )
                    })
                });
                if !completed {
                    self.journal
                        .aborted_signing_sessions
                        .insert(session.clone());
                }
            }
            for saved in self.journal.commands.values_mut() {
                if missing.contains(&saved.request.envelope().destination_enclave)
                    && matches!(
                        &saved.request.request().command.command,
                        EnclaveCommand::Musig(MusigCommand::Keygen(KeygenCommand::Escrow(command)))
                            if command.context.operation == keymeld_core::escrow::protocol::Operation::Execute
                    )
                {
                    // Execute restores its sealed preparation and binding before
                    // reinstalling effects. Retain Bind/Prepare outputs: repeating
                    // Prepare could otherwise create a different external invoice.
                    saved.outcome = None;
                }
            }
            self.checkpoint.save(self.journal).await?;
            // Replay the exact saved keygen commands, keeping their original
            // authenticated results. Newly randomized peer-key ciphertext must
            // not replace a previously committed distribution transcript.
            for stage in ["keygen/init", "keygen/register", "keygen/distribute"] {
                for id in &missing {
                    let key = format!("{stage}/{}", id.as_u32());
                    if !self.journal.commands.contains_key(&key) {
                        if stage == "keygen/distribute" && self.enclaves.len() == 1 {
                            continue;
                        }
                        return Err(invalid("Missing original keygen restoration request"));
                    }
                    self.replay_recorded(stage, *id).await?;
                }
            }
            for id in &missing {
                let enclave = &self.enclaves[id];
                let request = self.transport.prepare(
                    enclave,
                    route_id,
                    Command::new(EnclaveCommand::Musig(MusigCommand::Keygen(
                        KeygenCommand::GetAggregatePublicKey(GetAggregatePublicKeyCommand {
                            keygen_session_id: self.manifest.manifest.keygen_session_id.clone(),
                        }),
                    ))),
                    self.authority,
                    self.reply_key,
                )?;
                let EnclaveOutcome::Musig(MusigOutcome::Keygen(KeygenOutcome::AggregatePublicKey(
                    response,
                ))) = self
                    .transport
                    .execute(enclave, &request, self.reply_key)
                    .await?
                    .response
                else {
                    return Err(invalid("Restored keygen is incomplete"));
                };
                self.verify_roster_from(*id, response, registrations)?;
            }
        }
        self.complete_keygen(registrations).await
    }

    pub async fn complete_keygen(
        &mut self,
        registrations: &BTreeMap<UserId, ParticipantRegistrationData>,
    ) -> Result<SignedRoster, SdkError> {
        if registrations.keys().collect::<BTreeSet<_>>()
            != self
                .manifest
                .manifest
                .participant_verifiers
                .keys()
                .collect()
        {
            return Err(invalid(
                "Keygen requires the complete authorized registration roster",
            ));
        }
        let grouped = self.group_registrations(registrations)?;
        let coordinator_enclave =
            self.recipients.user_enclave_assignments[&self.manifest.manifest.coordinator_user_id];
        for enclave_id in grouped.keys().copied().collect::<Vec<_>>() {
            self.init_keygen(enclave_id).await?;
        }
        let mut distributed: BTreeMap<EnclaveId, BTreeMap<UserId, String>> = BTreeMap::new();
        for (enclave_id, local) in &grouped {
            for (target, user, key) in self.register_participants(*enclave_id, local).await? {
                distributed.entry(target).or_default().insert(user, key);
            }
        }
        for (enclave_id, keys) in distributed {
            let session = self.manifest.manifest.keygen_session_id.clone();
            let entries: Vec<_> = keys.into_iter().collect();
            let copy = entries.clone();
            let response = self
                .command_once("keygen/distribute", enclave_id, &entries, move || {
                    Ok(EnclaveCommand::Musig(MusigCommand::Keygen(
                        KeygenCommand::DistributeParticipantPublicKeysBatch(
                            DistributeParticipantPublicKeysBatchCommand {
                                keygen_session_id: session,
                                participants_public_keys: copy,
                            },
                        ),
                    )))
                })
                .await?;
            // The batch that completes distribution moves the session to Completed
            // and answers with the aggregate key instead of a bare acknowledgement.
            // Both are successful outcomes; the authoritative roster is fetched and
            // verified separately below, so this response body is not needed here.
            if !matches!(
                response,
                EnclaveOutcome::Musig(MusigOutcome::Keygen(
                    KeygenOutcome::Success | KeygenOutcome::AggregatePublicKey(_)
                ))
            ) {
                return Err(invalid("Unexpected confidential key distribution result"));
            }
        }
        let session = self.manifest.manifest.keygen_session_id.clone();
        let response = self
            .command_once("keygen/aggregate", coordinator_enclave, &(), move || {
                Ok(EnclaveCommand::Musig(MusigCommand::Keygen(
                    KeygenCommand::GetAggregatePublicKey(GetAggregatePublicKeyCommand {
                        keygen_session_id: session,
                    }),
                )))
            })
            .await?;
        let EnclaveOutcome::Musig(MusigOutcome::Keygen(KeygenOutcome::AggregatePublicKey(
            response,
        ))) = response
        else {
            return Err(invalid("Unexpected confidential aggregate-key result"));
        };
        self.verify_roster(response, registrations)
    }

    /// Check each registration against the manifest and its assigned enclave, grouped by
    /// the enclave that holds it.
    fn group_registrations(
        &self,
        registrations: &BTreeMap<UserId, ParticipantRegistrationData>,
    ) -> Result<BTreeMap<EnclaveId, Vec<ParticipantRegistrationData>>, SdkError> {
        let mut grouped: BTreeMap<EnclaveId, Vec<ParticipantRegistrationData>> = BTreeMap::new();
        for (user, registration) in registrations {
            if user != &registration.user_id {
                return Err(invalid("Registration map substituted a participant"));
            }
            registration
                .registration_authorization
                .verify(self.manifest, &registration.enclave_encrypted_data)?;
            grouped
                .entry(self.registration_enclave(registration)?)
                .or_default()
                .push(registration.clone());
        }
        Ok(grouped)
    }

    /// Initialize the keygen session on one enclave, for every participant the manifest
    /// authorized.
    async fn init_keygen(&mut self, enclave_id: EnclaveId) -> Result<(), SdkError> {
        let enclave_keys = self
            .recipients
            .recipient_public_keys
            .iter()
            .map(|(enclave_id, key)| EnclavePublicKeyInfo {
                enclave_id: *enclave_id,
                public_key: hex::encode(key),
            })
            .collect::<Vec<_>>();
        let expected = self
            .manifest
            .manifest
            .participant_verifiers
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let coordinator_enclave =
            self.recipients.user_enclave_assignments[&self.manifest.manifest.coordinator_user_id];
        let manifest = self.manifest.clone();
        let recipients = self.recipients.clone();
        let credentials = self.credentials;
        let key = hex::encode(&self.recipients.recipient_public_keys[&enclave_id]);
        let response = self
            .command_once("keygen/init", enclave_id, &(), move || {
                Ok(EnclaveCommand::Musig(MusigCommand::Keygen(
                    KeygenCommand::InitSession(InitKeygenSessionCommand {
                        keygen_session_id: manifest.manifest.keygen_session_id.clone(),
                        coordinator_encrypted_private_key: None,
                        coordinator_user_id: (enclave_id == coordinator_enclave)
                            .then(|| manifest.manifest.coordinator_user_id.clone()),
                        encrypted_session_secret: Some(
                            credentials.encrypt_secret_for_enclave(&key)?,
                        ),
                        timeout_secs: manifest.manifest.timeout_secs,
                        expected_participant_count: expected.len(),
                        expected_participants: expected,
                        enclave_public_keys: enclave_keys,
                        encrypted_taproot_tweak: manifest.manifest.encrypted_taproot_tweak.clone(),
                        subset_definitions: manifest.manifest.subset_definitions.clone(),
                        recipient_authorization: Box::new(recipients),
                        authorization_manifest: Box::new(manifest),
                    }),
                )))
            })
            .await?;
        match response {
            EnclaveOutcome::Musig(MusigOutcome::Keygen(KeygenOutcome::KeygenInitialized(
                value,
            ))) if value.keygen_session_id == self.manifest.manifest.keygen_session_id => Ok(()),
            EnclaveOutcome::Musig(MusigOutcome::Keygen(KeygenOutcome::Success)) => Ok(()),
            _ => Err(invalid(
                "Unexpected confidential keygen initialization result",
            )),
        }
    }

    /// Register one enclave's participants. Returns the public key it encrypted for each peer
    /// enclave, as `(peer, participant, ciphertext)`.
    async fn register_participants(
        &mut self,
        enclave_id: EnclaveId,
        local: &[ParticipantRegistrationData],
    ) -> Result<Vec<(EnclaveId, UserId, String)>, SdkError> {
        let participants = local.to_vec();
        let copy = participants.clone();
        let session = self.manifest.manifest.keygen_session_id.clone();
        let response = self
            .command_once("keygen/register", enclave_id, &participants, move || {
                Ok(EnclaveCommand::Musig(MusigCommand::Keygen(
                    KeygenCommand::AddParticipantsBatch(AddParticipantsBatchCommand {
                        keygen_session_id: session,
                        participants: copy,
                    }),
                )))
            })
            .await?;
        let EnclaveOutcome::Musig(MusigOutcome::Keygen(KeygenOutcome::ParticipantsAddedBatch(
            response,
        ))) = response
        else {
            return Err(invalid("Unexpected confidential participant batch result"));
        };
        let expected: BTreeSet<_> = local.iter().map(|p| &p.user_id).collect();
        if response.participants.len() != expected.len()
            || response.participants.iter().collect::<BTreeSet<_>>() != expected
            || response.encrypted_public_keys.len() != expected.len()
        {
            return Err(invalid("Enclave changed the registered participant set"));
        }
        let mut seen = BTreeSet::new();
        let mut peer_keys = Vec::new();
        for (user, keys) in response.encrypted_public_keys {
            if !expected.contains(&user) || !seen.insert(user.clone()) {
                return Err(invalid(
                    "Enclave returned duplicate or foreign participant keys",
                ));
            }
            let mut destinations = BTreeSet::new();
            for key in keys {
                if !self.enclaves.contains_key(&key.target_enclave_id)
                    || key.target_enclave_id == enclave_id
                    || !destinations.insert(key.target_enclave_id)
                {
                    return Err(invalid(
                        "Enclave returned an unapproved public-key destination",
                    ));
                }
                peer_keys.push((
                    key.target_enclave_id,
                    user.clone(),
                    key.encrypted_public_key,
                ));
            }
            if destinations.len() != self.enclaves.len().saturating_sub(1) {
                return Err(invalid("Enclave omitted a required public-key recipient"));
            }
        }
        Ok(peer_keys)
    }

    /// Which of `enclaves` do not hold this keygen session, as after a restart. A fresh
    /// read-only challenge prevents a cached presence response from concealing one.
    async fn missing_keygen_sessions(
        &self,
        route_id: Uuid,
        enclaves: &[EnclaveId],
    ) -> Result<BTreeSet<EnclaveId>, SdkError> {
        let mut missing = BTreeSet::new();
        for id in enclaves {
            let enclave = self
                .enclaves
                .get(id)
                .ok_or_else(|| invalid("Unapproved confidential recipient"))?;
            let request = self.transport.prepare(
                enclave,
                route_id,
                Command::new(EnclaveCommand::System(SystemCommand::CheckKeygenSession {
                    keygen_session_id: self.manifest.manifest.keygen_session_id.clone(),
                    recipient_authorization: Box::new(self.recipients.clone()),
                })),
                self.authority,
                self.reply_key,
            )?;
            match self
                .transport
                .execute(enclave, &request, self.reply_key)
                .await?
                .response
            {
                EnclaveOutcome::System(SystemOutcome::KeygenSessionPresent(true)) => {}
                EnclaveOutcome::System(SystemOutcome::KeygenSessionPresent(false)) => {
                    missing.insert(*id);
                }
                _ => {
                    return Err(invalid(
                        "Cannot authenticate completed confidential keygen state",
                    ))
                }
            }
        }
        Ok(missing)
    }

    /// Send a journaled request again, exactly, and keep the outcome first recorded for it.
    ///
    /// An enclave that restarted and lost the session applies it again. A new outcome would
    /// hold newly randomized ciphertext, so the journal keeps the original.
    async fn replay_recorded(&self, stage: &str, enclave_id: EnclaveId) -> Result<(), SdkError> {
        let saved = self
            .journal
            .commands
            .get(&format!("{stage}/{}", enclave_id.as_u32()))
            .ok_or_else(|| invalid("Missing journaled request to replay"))?;
        let enclave = self
            .enclaves
            .get(&enclave_id)
            .ok_or_else(|| invalid("Unapproved confidential recipient"))?;
        let outcome = self
            .transport
            .execute(enclave, &saved.request, self.reply_key)
            .await?;
        if matches!(outcome.response, EnclaveOutcome::Error(_)) {
            return Err(invalid("Enclave rejected exact keygen restoration"));
        }
        Ok(())
    }

    fn verify_roster(
        &self,
        response: AggregatePublicKeyResponse,
        registrations: &BTreeMap<UserId, ParticipantRegistrationData>,
    ) -> Result<SignedRoster, SdkError> {
        let coordinator =
            self.recipients.user_enclave_assignments[&self.manifest.manifest.coordinator_user_id];
        self.verify_roster_from(coordinator, response, registrations)
    }

    fn verify_roster_from(
        &self,
        coordinator: EnclaveId,
        response: AggregatePublicKeyResponse,
        registrations: &BTreeMap<UserId, ParticipantRegistrationData>,
    ) -> Result<SignedRoster, SdkError> {
        let roster: SignedRoster = serde_json::from_slice(
            &self
                .credentials
                .decrypt(&response.encrypted_roster, ROSTER_CONTEXT)?,
        )?;
        roster.verify(&self.recipients.recipient_public_keys[&coordinator])?;
        roster.verify_registrations(self.manifest)?;
        roster.roster.verify_aggregates()?;
        if response.keygen_session_id != self.manifest.manifest.keygen_session_id
            || response.participant_count != registrations.len()
            || self.credentials.decrypt(
                &response.encrypted_aggregate_public_key,
                "aggregate_public_key",
            )? != roster.roster.aggregate_public_key
            || response.encrypted_subset_aggregates.len()
                != roster.roster.subset_aggregate_keys.len()
        {
            return Err(invalid(
                "Aggregate result differs from the authenticated roster",
            ));
        }
        let tweak: keymeld_core::protocol::TaprootTweak =
            serde_json::from_slice(&self.credentials.decrypt(
                &self.manifest.manifest.encrypted_taproot_tweak,
                "taproot_tweak",
            )?)?;
        if serde_json::to_vec(&tweak)? != serde_json::to_vec(&roster.roster.taproot_tweak)? {
            return Err(invalid("Aggregate result changed the approved tweak"));
        }
        for (user, expected) in registrations {
            let actual = roster
                .roster
                .registrations
                .get(user)
                .ok_or_else(|| invalid("Roster omitted an accepted registration"))?;
            if serde_json::to_vec(actual)?
                != serde_json::to_vec(&expected.registration_authorization)?
            {
                return Err(invalid("Roster changed an accepted registration"));
            }
        }
        for (id, expected) in &roster.roster.subset_aggregate_keys {
            let encrypted = response
                .encrypted_subset_aggregates
                .get(id)
                .ok_or_else(|| invalid("Missing subset aggregate"))?;
            if &self
                .credentials
                .decrypt(encrypted, SUBSET_AGGREGATE_CONTEXT)?
                != expected
            {
                return Err(invalid(
                    "Subset aggregate differs from the authenticated roster",
                ));
            }
        }
        Ok(roster)
    }

    /// Freeze stable ciphertexts and identifiers before escrow preparation.
    pub async fn prepare_signing_batch(
        &mut self,
        session: &SessionId,
        items: &[BatchSigningItem],
    ) -> Result<Vec<EnclaveBatchItem>, SdkError> {
        if items.is_empty() || items.len() > keymeld_core::escrow::MAX_BATCH_ITEMS {
            return Err(invalid("Invalid confidential signing batch size"));
        }
        let unique = items
            .iter()
            .map(BatchSigningItem::id)
            .collect::<BTreeSet<_>>();
        if unique.len() != items.len() || unique.iter().any(Uuid::is_nil) || session.uuid().is_nil()
        {
            return Err(invalid(
                "Signing session and item identifiers must be unique and nonempty",
            ));
        }
        let session_tweak: keymeld_core::protocol::TaprootTweak =
            serde_json::from_slice(&self.credentials.decrypt(
                &self.manifest.manifest.encrypted_taproot_tweak,
                "taproot_tweak",
            )?)?;
        for item in items {
            if let Some(subset) = item.subset_id() {
                if !self
                    .manifest
                    .manifest
                    .subset_definitions
                    .iter()
                    .any(|definition| definition.subset_id == subset)
                    || serde_json::to_vec(item.taproot_tweak())?
                        != serde_json::to_vec(&session_tweak)?
                {
                    return Err(invalid(
                        "Subset item must use its authorized keygen tweak and subset",
                    ));
                }
            }
        }
        let commitment = authorization_digest("confidential-signing-batch-v1", &(session, items))?;
        if let Some(saved) = self.journal.signing_batches.get(session) {
            if saved.input_commitment != commitment {
                return Err(invalid("Signing retry changed its approved batch"));
            }
        } else {
            if self.journal.signing_batches.len() >= MAX_JOURNAL_COMMANDS {
                return Err(invalid("Confidential signing-session limit reached"));
            }
            let batch = items
                .iter()
                .map(|item| {
                    let encrypted_adaptor_configs = match item.mode() {
                        BatchSigningMode::Regular => None,
                        BatchSigningMode::Adaptor { configs } => {
                            keymeld_core::validation::validate_decrypted_adaptor_configs(configs)?;
                            Some(
                                self.credentials
                                    .encrypt(&serde_json::to_vec(configs)?, "adaptor_configs")?,
                            )
                        }
                    };
                    Ok(EnclaveBatchItem {
                        batch_item_id: item.id(),
                        encrypted_message: self
                            .credentials
                            .encrypt(hex::encode(item.message()).as_bytes(), "session_data")?,
                        encrypted_adaptor_configs,
                        encrypted_taproot_tweak: self
                            .credentials
                            .encrypt(&serde_json::to_vec(item.taproot_tweak())?, "session_data")?,
                        subset_id: item.subset_id(),
                    })
                })
                .collect::<Result<Vec<_>, SdkError>>()?;
            self.journal.signing_batches.insert(
                session.clone(),
                SavedBatch {
                    input_commitment: commitment,
                    items: batch,
                },
            );
        }
        self.checkpoint.save(self.journal).await?;
        Ok(self.journal.signing_batches[session].items.clone())
    }

    /// Decrypt native results for published batch parsers. The outer response
    /// must already have passed confidential enclave authentication.
    pub fn decrypt_batch_results(
        &self,
        results: &[EnclaveBatchResult],
    ) -> Result<Vec<crate::SignatureResult>, SdkError> {
        decrypt_batch_results(self.credentials, results)
    }

    /// Execute only after every required escrow permit has been installed.
    pub async fn sign_prepared_batch(
        &mut self,
        session: &SessionId,
        timeout_secs: u64,
        approvals: &[ParticipantApproval],
    ) -> Result<Vec<EnclaveBatchResult>, SdkError> {
        let items = self
            .journal
            .signing_batches
            .get(session)
            .ok_or_else(|| invalid("Signing batch was not durably prepared"))?
            .items
            .clone();
        if self.journal.aborted_signing_sessions.contains(session) {
            return Err(invalid("Enclave restart invalidated this unfinished signing round; authorize a fresh signing session"));
        }
        let secret = zeroize::Zeroizing::new(self.authority.export_secret());
        let signing_authorization = SigningAuthorization::sign(
            &secret,
            &self.manifest.manifest.keygen_session_id,
            session,
            timeout_secs,
            &items,
        )?;
        let mut grouped: BTreeMap<EnclaveId, Vec<UserId>> = BTreeMap::new();
        for (user, enclave) in &self.recipients.user_enclave_assignments {
            grouped.entry(*enclave).or_default().push(user.clone());
        }
        let mut nonces = BTreeMap::new();
        for (enclave_id, users) in &grouped {
            let cmd = InitSigningSessionCommand {
                keygen_session_id: self.manifest.manifest.keygen_session_id.clone(),
                signing_session_id: session.clone(),
                signing_authorization: signing_authorization.clone(),
                user_ids: users.clone(),
                encrypted_taproot_tweak: self.manifest.manifest.encrypted_taproot_tweak.clone(),
                expected_participant_count: self.recipients.user_enclave_assignments.len(),
                approval_signatures: approvals.to_vec(),
                batch_items: items.clone(),
            };
            let copy = cmd.clone();
            let result = self
                .command_once(
                    &format!("sign/{session}/nonces"),
                    *enclave_id,
                    &cmd,
                    move || {
                        Ok(EnclaveCommand::Musig(MusigCommand::Signing(
                            SigningCommand::InitSession(copy),
                        )))
                    },
                )
                .await?;
            let EnclaveOutcome::Musig(MusigOutcome::Signing(SigningOutcome::Nonces(response))) =
                result
            else {
                return Err(invalid("Unexpected confidential nonce-round result"));
            };
            if response.signing_session_id != *session
                || response.keygen_session_id != self.manifest.manifest.keygen_session_id
            {
                return Err(invalid("Nonce round returned another session"));
            }
            collect_peer_values(users, response.nonces, &mut nonces)?;
        }
        let nonces: Vec<_> = nonces.into_iter().collect();
        let mut partials = BTreeMap::new();
        for (enclave_id, users) in &grouped {
            let cmd = DistributeNoncesCommand {
                signing_session_id: session.clone(),
                nonces: nonces.clone(),
            };
            let copy = cmd.clone();
            let result = self
                .command_once(
                    &format!("sign/{session}/partials"),
                    *enclave_id,
                    &cmd,
                    move || {
                        Ok(EnclaveCommand::Musig(MusigCommand::Signing(
                            SigningCommand::DistributeNonces(copy),
                        )))
                    },
                )
                .await?;
            let EnclaveOutcome::Musig(MusigOutcome::Signing(SigningOutcome::PartialSignature(
                response,
            ))) = result
            else {
                return Err(invalid("Unexpected confidential partial-signature result"));
            };
            collect_peer_values(users, response.partial_signatures, &mut partials)?;
        }
        let coordinator =
            self.recipients.user_enclave_assignments[&self.manifest.manifest.coordinator_user_id];
        let cmd = FinalizeSignatureCommand {
            signing_session_id: session.clone(),
            partial_signatures: partials.into_iter().collect(),
        };
        let copy = cmd.clone();
        let result = self
            .command_once(
                &format!("sign/{session}/final"),
                coordinator,
                &cmd,
                move || {
                    Ok(EnclaveCommand::Musig(MusigCommand::Signing(
                        SigningCommand::FinalizeSignature(copy),
                    )))
                },
            )
            .await?;
        let EnclaveOutcome::Musig(MusigOutcome::Signing(SigningOutcome::FinalSignature(response))) =
            result
        else {
            return Err(invalid(
                "Unexpected confidential signature aggregation result",
            ));
        };
        let expected: BTreeSet<_> = items.iter().map(|item| item.batch_item_id).collect();
        if response.signing_session_id != *session
            || response.keygen_session_id != self.manifest.manifest.keygen_session_id
            || response.participant_count != self.recipients.user_enclave_assignments.len()
            || response.batch_results.len() != expected.len()
            || response
                .batch_results
                .iter()
                .map(|item| item.batch_item_id)
                .collect::<BTreeSet<_>>()
                != expected
        {
            return Err(invalid(
                "Final signing result differs from the authorized batch",
            ));
        }
        Ok(response.batch_results)
    }
}

fn collect_peer_values(
    expected: &[UserId],
    values: Vec<(UserId, String)>,
    output: &mut BTreeMap<UserId, String>,
) -> Result<(), SdkError> {
    let expected: BTreeSet<_> = expected.iter().collect();
    if values.len() != expected.len()
        || values.iter().map(|(user, _)| user).collect::<BTreeSet<_>>() != expected
    {
        return Err(invalid(
            "Protocol round omitted or substituted an assigned participant",
        ));
    }
    for (user, value) in values {
        if value.is_empty() || output.insert(user, value).is_some() {
            return Err(invalid(
                "Protocol round returned an empty or duplicate contribution",
            ));
        }
    }
    Ok(())
}

pub fn decrypt_batch_results(
    credentials: &SessionCredentials,
    results: &[EnclaveBatchResult],
) -> Result<Vec<crate::SignatureResult>, SdkError> {
    let mut seen = BTreeSet::new();
    results
        .iter()
        .map(|result| {
            if !seen.insert(result.batch_item_id) {
                return Err(invalid("Duplicate signing result identifier"));
            }
            let signature = result
                .encrypted_final_signature
                .as_ref()
                .map(|ciphertext| credentials.decrypt(ciphertext, "signature"))
                .transpose()?;
            let adaptor_signatures = result
                .encrypted_adaptor_signatures
                .as_ref()
                .map(|ciphertext| {
                    let plaintext = credentials.decrypt(ciphertext, "adaptor_signatures")?;
                    Ok::<_, SdkError>(serde_json::from_slice(&plaintext)?)
                })
                .transpose()?;
            Ok(crate::SignatureResult {
                batch_item_id: result.batch_item_id,
                signature,
                adaptor_signatures,
                error: result.error.clone(),
            })
        })
        .collect()
}
