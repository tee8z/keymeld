use std::collections::{BTreeMap, BTreeSet};

use crate::client::KeyMeldClient;
use crate::credentials::{AuthorizationCredentials, SessionCredentials};
use crate::error::{KeygenError, SdkError};
use crate::types::{
    GetAvailableSlotsResponse, InitializeKeygenSessionRequest, InitializeKeygenSessionResponse,
    KeygenSessionStatusResponse, KeygenStatusKind, RegisterKeygenParticipantRequest,
    RegisterKeygenParticipantResponse, ReserveKeygenSessionRequest, ReserveKeygenSessionResponse,
    SessionId, SubsetDefinition, TaprootTweak, UserId,
};
use keymeld_core::authorization::{
    RegistrationAuthorization, RegistrationContext, SessionAuthorizationManifest, SignedRoster,
    SignedSessionManifest, ROSTER_CONTEXT, SUBSET_AGGREGATE_CONTEXT,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct KeygenOptions {
    pub(crate) timeout_secs: Option<u64>,
    pub(crate) max_signing_sessions: Option<u32>,
    pub(crate) taproot_tweak: TaprootTweak,
    pub(crate) require_signing_approval: bool,
    pub(crate) authority: Option<AuthorizationCredentials>,
    pub(crate) participant_verifiers: BTreeMap<UserId, Vec<u8>>,
}

impl KeygenOptions {
    pub fn authorization_credentials(mut self, credentials: AuthorizationCredentials) -> Self {
        self.authority = Some(credentials);
        self
    }

    pub fn participant_verifiers(mut self, verifiers: BTreeMap<UserId, Vec<u8>>) -> Self {
        self.participant_verifiers = verifiers;
        self
    }

    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = Some(secs);
        self
    }

    pub fn max_signings(mut self, count: u32) -> Self {
        self.max_signing_sessions = Some(count);
        self
    }

    pub fn tweak(mut self, tweak: TaprootTweak) -> Self {
        self.taproot_tweak = tweak;
        self
    }

    pub fn require_approval(mut self) -> Self {
        self.require_signing_approval = true;
        self
    }

    pub fn approval(mut self, required: bool) -> Self {
        self.require_signing_approval = required;
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct JoinOptions {
    pub(crate) require_signing_approval: bool,
    registration_credentials: Option<AuthorizationCredentials>,
    authorization_manifest: Option<SignedSessionManifest>,
}

#[derive(Debug, Clone)]
pub struct ParticipantInvitation {
    pub authorization_manifest: SignedSessionManifest,
    pub registration_credentials: AuthorizationCredentials,
}

impl JoinOptions {
    pub fn registration_credentials(mut self, credentials: AuthorizationCredentials) -> Self {
        self.registration_credentials = Some(credentials);
        self
    }

    pub fn authorization_manifest(mut self, manifest: SignedSessionManifest) -> Self {
        self.authorization_manifest = Some(manifest);
        self
    }

    pub fn invitation(self, invitation: ParticipantInvitation) -> Self {
        self.registration_credentials(invitation.registration_credentials)
            .authorization_manifest(invitation.authorization_manifest)
    }

    pub fn require_approval(mut self) -> Self {
        self.require_signing_approval = true;
        self
    }

    pub fn approval(mut self, required: bool) -> Self {
        self.require_signing_approval = required;
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct RegisterOptions {
    pub(crate) require_signing_approval: bool,
    registration_credentials: Option<AuthorizationCredentials>,
}

impl RegisterOptions {
    pub fn registration_credentials(mut self, credentials: AuthorizationCredentials) -> Self {
        self.registration_credentials = Some(credentials);
        self
    }

    pub fn require_approval(mut self) -> Self {
        self.require_signing_approval = true;
        self
    }

    pub fn approval(mut self, required: bool) -> Self {
        self.require_signing_approval = required;
        self
    }
}

pub struct KeygenManager<'a> {
    client: &'a KeyMeldClient,
}

impl<'a> KeygenManager<'a> {
    pub(crate) fn new(client: &'a KeyMeldClient) -> Self {
        Self { client }
    }

    pub async fn create_session(
        &self,
        participants: Vec<UserId>,
        options: KeygenOptions,
    ) -> Result<KeygenSession<'a>, SdkError> {
        self.create_session_internal(participants, vec![], options)
            .await
    }

    pub async fn create_session_with_subsets(
        &self,
        participants: Vec<UserId>,
        subsets: Vec<SubsetDefinition>,
        options: KeygenOptions,
    ) -> Result<KeygenSession<'a>, SdkError> {
        self.create_session_internal(participants, subsets, options)
            .await
    }

    async fn create_session_internal(
        &self,
        participants: Vec<UserId>,
        subsets: Vec<SubsetDefinition>,
        options: KeygenOptions,
    ) -> Result<KeygenSession<'a>, SdkError> {
        let user_credentials = self.client.credentials().ok_or_else(|| {
            SdkError::InvalidInput(
                "User credentials required for creating keygen session".to_string(),
            )
        })?;

        let credentials = SessionCredentials::generate()?;

        let keygen_session_id = SessionId::new_v7();

        let encrypted_taproot_tweak = credentials.encrypt(
            &serde_json::to_vec(&options.taproot_tweak)
                .map_err(|e| SdkError::Internal(format!("Failed to serialize tweak: {}", e)))?,
            "taproot_tweak",
        )?;

        let authority = match options.authority.clone() {
            Some(authority) => authority,
            None => AuthorizationCredentials::generate()?,
        };
        let mut registration_credentials = BTreeMap::new();
        let mut participant_verifiers = BTreeMap::new();
        for participant in &participants {
            if let Some(verifier) = options.participant_verifiers.get(participant) {
                participant_verifiers.insert(participant.clone(), verifier.clone());
            } else {
                let credential = AuthorizationCredentials::generate()?;
                participant_verifiers.insert(participant.clone(), credential.public_key_bytes());
                registration_credentials.insert(participant.clone(), credential);
            }
        }
        if participants.len() != participant_verifiers.len()
            || options
                .participant_verifiers
                .keys()
                .any(|user| !participants.contains(user))
        {
            return Err(SdkError::InvalidInput(
                "Participant identities must be unique and expected".into(),
            ));
        }
        let authorization_manifest = SignedSessionManifest::sign(
            SessionAuthorizationManifest {
                keygen_session_id: keygen_session_id.clone(),
                coordinator_user_id: self.client.user_id().clone(),
                creator_pubkey: authority.public_key_bytes(),
                signing_pubkey: authority.public_key_bytes(),
                session_public_key: credentials.public_key_bytes(),
                participant_verifiers,
                timeout_secs: options.timeout_secs.unwrap_or(3600),
                max_signing_sessions: options.max_signing_sessions,
                encrypted_taproot_tweak: encrypted_taproot_tweak.clone(),
                subset_definitions: subsets
                    .iter()
                    .map(|subset| keymeld_core::protocol::SubsetDefinition {
                        subset_id: subset.subset_id,
                        participants: subset.participants.clone(),
                    })
                    .collect(),
            },
            &authority.export_secret(),
        )?;

        let reserve_request = ReserveKeygenSessionRequest {
            authorization_manifest: authorization_manifest.clone(),
            keygen_session_id: keygen_session_id.clone(),
            coordinator_user_id: self.client.user_id().clone(),
            expected_participants: participants.clone(),
            timeout_secs: options.timeout_secs.unwrap_or(3600),
            max_signing_sessions: options.max_signing_sessions,
            encrypted_taproot_tweak,
            subset_definitions: subsets,
        };

        let reserve_response: ReserveKeygenSessionResponse = self
            .client
            .http()
            .post(
                &self.client.url("/api/v1/keygen/reserve"),
                &reserve_request,
                &[],
            )
            .await?;

        if reserve_response.keygen_session_id != keygen_session_id
            || reserve_response.expected_participants != participants.len()
        {
            return Err(SdkError::InvalidInput(
                "Gateway returned a different keygen reservation".into(),
            ));
        }

        if reserve_response
            .user_enclave_assignments
            .get(self.client.user_id())
            != Some(&reserve_response.coordinator_enclave_id)
        {
            return Err(SdkError::InvalidInput(
                "Reservation changed coordinator assignment".into(),
            ));
        }
        let mut recipient_public_keys = BTreeMap::new();
        let recipient_ids: BTreeSet<_> = reserve_response
            .user_enclave_assignments
            .values()
            .copied()
            .collect();
        for enclave_id in recipient_ids {
            let enclave = self
                .client
                .health()
                .get_enclave_key(enclave_id.as_u32())
                .await?;
            if enclave_id == reserve_response.coordinator_enclave_id
                && (enclave.public_key != reserve_response.coordinator_public_key
                    || enclave.key_epoch != reserve_response.coordinator_key_epoch)
            {
                return Err(SdkError::InvalidInput(
                    "Reserved coordinator key or epoch changed".into(),
                ));
            }
            recipient_public_keys.insert(
                enclave_id,
                hex::decode(&enclave.public_key)
                    .map_err(|_| SdkError::InvalidInput("Invalid enclave recipient key".into()))?,
            );
        }
        let recipient_authorization =
            keymeld_core::authorization::EnclaveRecipientAuthorization::sign(
                &authorization_manifest,
                reserve_response.user_enclave_assignments,
                recipient_public_keys,
                &authority.export_secret(),
            )?;
        let encrypted_session_secret =
            credentials.encrypt_secret_for_enclave(&reserve_response.coordinator_public_key)?;

        let session_data = KeygenSessionData {
            coordinator_pubkey: user_credentials.public_key_bytes(),
            aggregate_pubkey: None,
        };
        let encrypted_session_data = credentials.encrypt(
            &serde_json::to_vec(&session_data).map_err(|e| {
                SdkError::Internal(format!("Failed to serialize session data: {}", e))
            })?,
            "keygen_session",
        )?;

        let mut initialize_request = InitializeKeygenSessionRequest {
            recipient_authorization: recipient_authorization.clone(),
            authorization_signature: Vec::new(),
            coordinator_pubkey: user_credentials.public_key_bytes(),
            session_public_key: credentials.public_key_bytes(),
            encrypted_session_secret,
            encrypted_session_data,
            enclave_key_epoch: reserve_response.coordinator_key_epoch,
        };

        initialize_request.sign_authorization(&keygen_session_id, &authority.export_secret())?;

        let init_response: InitializeKeygenSessionResponse = self
            .client
            .http()
            .post(
                &self
                    .client
                    .url(&format!("/api/v1/keygen/{}/initialize", keygen_session_id)),
                &initialize_request,
                &[],
            )
            .await?;

        if init_response.keygen_session_id != keygen_session_id
            || init_response.session_public_key != credentials.public_key_bytes()
        {
            return Err(SdkError::InvalidInput(
                "Gateway returned a different initialized keygen session".into(),
            ));
        }

        Ok(KeygenSession {
            recipient_authorization: Some(recipient_authorization),
            authorization_manifest,
            authority: Some(authority),
            registration_credentials,
            encrypted_roster: None,
            own_registration: None,
            require_signing_approval: options.require_signing_approval,
            roster_enclave_pubkey: reserve_response.coordinator_public_key.clone(),
            session_id: keygen_session_id,
            credentials,
            status: KeygenStatusKind::CollectingParticipants,
            aggregate_key: None,
            subset_aggregates: BTreeMap::new(),
            coordinator_enclave_pubkey: Some(reserve_response.coordinator_public_key),
            is_registered: false,
            client: self.client,
        })
    }

    pub async fn join_session(
        &self,
        session_id: SessionId,
        session_secret: &[u8; 32],
        options: JoinOptions,
    ) -> Result<KeygenSession<'a>, SdkError> {
        let credentials = SessionCredentials::from_session_secret(session_secret)?;
        let manifest = options.authorization_manifest.ok_or_else(|| {
            SdkError::InvalidInput(
                "A participant invitation must include the trusted authorization manifest".into(),
            )
        })?;
        let registration_credentials = options.registration_credentials.ok_or_else(|| {
            SdkError::InvalidInput(
                "Participant-scoped registration credentials are required".into(),
            )
        })?;
        let mut session = self
            .restore_session(session_id, credentials, manifest)
            .await?;
        session.is_registered = false;
        session
            .register_self(
                RegisterOptions::default()
                    .approval(options.require_signing_approval)
                    .registration_credentials(registration_credentials),
            )
            .await?;
        Ok(session)
    }

    pub async fn get_available_slots(
        &self,
        session_id: &SessionId,
        credentials: &SessionCredentials,
    ) -> Result<GetAvailableSlotsResponse, SdkError> {
        let signature = credentials.sign_session_request(&session_id.to_string())?;
        let response: GetAvailableSlotsResponse = self
            .client
            .http()
            .get(
                &self
                    .client
                    .url(&format!("/api/v1/keygen/{}/slots", session_id)),
                &[("X-Session-Signature", &signature)],
            )
            .await?;
        if &response.session_id != session_id {
            return Err(SdkError::InvalidInput(
                "Gateway returned participant slots for a different session".into(),
            ));
        }
        Ok(response)
    }

    pub async fn restore_session(
        &self,
        session_id: SessionId,
        credentials: SessionCredentials,
        authorization_manifest: SignedSessionManifest,
    ) -> Result<KeygenSession<'a>, SdkError> {
        authorization_manifest.verify()?;
        if authorization_manifest.manifest.keygen_session_id != session_id
            || authorization_manifest.manifest.session_public_key != credentials.public_key_bytes()
        {
            return Err(SdkError::InvalidInput(
                "Session credentials do not match the trusted manifest".into(),
            ));
        }
        let slots = self.get_available_slots(&session_id, &credentials).await?;
        let coordinator_slot = slots
            .available_slots
            .iter()
            .find(|slot| slot.user_id == authorization_manifest.manifest.coordinator_user_id)
            .ok_or_else(|| SdkError::InvalidInput("Coordinator slot is missing".into()))?;
        let coordinator_key = self
            .client
            .health()
            .get_enclave_key(coordinator_slot.enclave_id.as_u32())
            .await?;
        let mut session = KeygenSession {
            recipient_authorization: None,
            session_id,
            credentials,
            authorization_manifest,
            authority: None,
            registration_credentials: BTreeMap::new(),
            encrypted_roster: None,
            own_registration: None,
            require_signing_approval: false,
            roster_enclave_pubkey: coordinator_key.public_key,
            status: KeygenStatusKind::CollectingParticipants,
            aggregate_key: None,
            subset_aggregates: BTreeMap::new(),
            coordinator_enclave_pubkey: None,
            is_registered: true,
            client: self.client,
        };
        session.refresh_status().await?;
        Ok(session)
    }

    pub async fn restore_session_with_authority(
        &self,
        session_id: SessionId,
        credentials: SessionCredentials,
        authorization_manifest: SignedSessionManifest,
        authority: AuthorizationCredentials,
    ) -> Result<KeygenSession<'a>, SdkError> {
        if authority.public_key_bytes() != authorization_manifest.manifest.signing_pubkey {
            return Err(SdkError::InvalidInput(
                "Signing authority does not match the trusted manifest".into(),
            ));
        }
        let mut session = self
            .restore_session(session_id, credentials, authorization_manifest)
            .await?;
        session.authority = Some(authority);
        Ok(session)
    }
}

pub struct KeygenSession<'a> {
    recipient_authorization: Option<keymeld_core::authorization::EnclaveRecipientAuthorization>,
    authorization_manifest: SignedSessionManifest,
    authority: Option<AuthorizationCredentials>,
    registration_credentials: BTreeMap<UserId, AuthorizationCredentials>,
    encrypted_roster: Option<String>,
    own_registration: Option<RegistrationAuthorization>,
    require_signing_approval: bool,
    roster_enclave_pubkey: String,
    session_id: SessionId,
    credentials: SessionCredentials,
    status: KeygenStatusKind,
    aggregate_key: Option<crate::types::AggregatePublicKey>,
    subset_aggregates: BTreeMap<Uuid, String>,
    coordinator_enclave_pubkey: Option<String>,
    is_registered: bool,
    client: &'a KeyMeldClient,
}

impl<'a> KeygenSession<'a> {
    pub fn recipient_authorization(
        &self,
    ) -> Option<&keymeld_core::authorization::EnclaveRecipientAuthorization> {
        self.recipient_authorization.as_ref()
    }
    pub fn authorization_manifest(&self) -> &SignedSessionManifest {
        &self.authorization_manifest
    }
    pub fn authorization_credentials(&self) -> Option<&AuthorizationCredentials> {
        self.authority.as_ref()
    }
    pub fn registration_credentials(&self, user: &UserId) -> Option<&AuthorizationCredentials> {
        self.registration_credentials.get(user)
    }
    pub fn invitation(&self, user: &UserId) -> Result<ParticipantInvitation, SdkError> {
        let credential = self.registration_credentials.get(user).ok_or_else(|| {
            SdkError::InvalidInput(
                "This client does not hold that participant's registration credential".into(),
            )
        })?;
        Ok(ParticipantInvitation {
            authorization_manifest: self.authorization_manifest.clone(),
            registration_credentials: credential.clone(),
        })
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn status(&self) -> &KeygenStatusKind {
        &self.status
    }

    pub fn credentials(&self) -> &SessionCredentials {
        &self.credentials
    }

    pub fn is_registered(&self) -> bool {
        self.is_registered
    }

    pub fn coordinator_enclave_pubkey(&self) -> Option<&str> {
        self.coordinator_enclave_pubkey.as_deref()
    }

    pub async fn register_self(
        &mut self,
        options: RegisterOptions,
    ) -> Result<&KeygenStatusKind, SdkError> {
        if self.is_registered {
            return Err(SdkError::InvalidInput(
                "Already registered as a participant".to_string(),
            ));
        }

        let slots = self
            .client
            .keygen()
            .get_available_slots(&self.session_id, &self.credentials)
            .await?;
        let slot = slots
            .available_slots
            .iter()
            .find(|slot| &slot.user_id == self.client.user_id() && !slot.claimed)
            .ok_or_else(|| {
                SdkError::Keygen(KeygenError::NoAvailableSlots(self.session_id.clone()))
            })?;
        let enclave = self
            .client
            .health()
            .get_enclave_key(slot.enclave_id.as_u32())
            .await?;
        let enclave_pubkey = &enclave.public_key;
        let recipients = self.recipient_authorization.as_ref().ok_or_else(|| {
            SdkError::InvalidInput("Missing authorized enclave recipients".into())
        })?;
        if recipients
            .user_enclave_assignments
            .get(self.client.user_id())
            != Some(&slot.enclave_id)
            || recipients.recipient_public_keys.get(&slot.enclave_id)
                != Some(
                    &hex::decode(enclave_pubkey)
                        .map_err(|_| SdkError::InvalidInput("Invalid enclave key".into()))?,
                )
        {
            return Err(SdkError::InvalidInput(
                "Participant enclave differs from the creator's authorized recipient".into(),
            ));
        }
        let enclave_key_epoch = enclave.key_epoch;
        let registration_credentials = options
            .registration_credentials
            .as_ref()
            .or_else(|| self.registration_credentials.get(self.client.user_id()))
            .ok_or_else(|| {
                SdkError::InvalidInput(
                    "Participant-scoped registration credentials are required".into(),
                )
            })?;
        if self
            .authorization_manifest
            .manifest
            .participant_verifiers
            .get(self.client.user_id())
            != Some(&registration_credentials.public_key_bytes())
        {
            return Err(SdkError::InvalidInput(
                "Registration credential does not match this participant's slot".into(),
            ));
        }

        let user_credentials = self.client.credentials().ok_or_else(|| {
            SdkError::InvalidInput("User credentials required for registration".to_string())
        })?;

        let session_signature = self
            .credentials
            .sign_session_request(&self.session_id.to_string())?;

        let context = RegistrationContext {
            keygen_session_id: self.session_id.clone(),
            manifest_hash: self.authorization_manifest.digest()?,
            user_id: self.client.user_id().clone(),
            enclave_id: slot.enclave_id,
            enclave_key_epoch,
            public_key: user_credentials.public_key_bytes(),
            auth_pubkey: user_credentials
                .derive_session_auth_pubkey(&self.session_id.to_string())?,
            require_signing_approval: options.require_signing_approval
                || self.require_signing_approval,
        };
        let encrypted_private_key =
            user_credentials.prepare_registration(context.clone(), enclave_pubkey)?;
        let registration_authorization = RegistrationAuthorization::sign(
            &registration_credentials.export_secret(),
            context,
            &encrypted_private_key,
        )?;

        let session_data = KeygenParticipantSessionData {
            participant_public_keys: {
                let mut map = BTreeMap::new();
                map.insert(
                    self.client.user_id().clone(),
                    user_credentials.public_key_bytes(),
                );
                map
            },
        };
        let encrypted_session_data = self.credentials.encrypt(
            &serde_json::to_vec(&session_data)
                .map_err(|e| SdkError::Internal(format!("Failed to serialize: {}", e)))?,
            "keygen_participant_session",
        )?;

        let auth_pubkey =
            user_credentials.derive_session_auth_pubkey(&self.session_id.to_string())?;

        let register_request = RegisterKeygenParticipantRequest {
            registration_authorization,
            keygen_session_id: self.session_id.clone(),
            user_id: self.client.user_id().clone(),
            encrypted_private_key,
            public_key: user_credentials.public_key_bytes(),
            encrypted_session_data,
            enclave_public_key: enclave_pubkey.clone(),
            enclave_key_epoch,
            require_signing_approval: options.require_signing_approval
                || self.require_signing_approval,
            auth_pubkey,
        };

        let response: RegisterKeygenParticipantResponse = self
            .client
            .http()
            .post(
                &self
                    .client
                    .url(&format!("/api/v1/keygen/{}/participants", self.session_id)),
                &register_request,
                &[("X-Session-Signature", &session_signature)],
            )
            .await?;

        if response.keygen_session_id != self.session_id
            || &response.user_id != self.client.user_id()
            || response.assigned_enclave_id != slot.enclave_id
            || response.require_signing_approval != register_request.require_signing_approval
        {
            return Err(SdkError::InvalidInput(
                "Gateway returned a different participant registration".into(),
            ));
        }

        self.status = response.status;
        self.own_registration = Some(register_request.registration_authorization);
        self.is_registered = true;

        Ok(&self.status)
    }

    pub async fn refresh_status(&mut self) -> Result<&KeygenStatusKind, SdkError> {
        let session_signature = self
            .credentials
            .sign_session_request(&self.session_id.to_string())?;

        let response: KeygenSessionStatusResponse = self
            .client
            .http()
            .get(
                &self
                    .client
                    .url(&format!("/api/v1/keygen/{}/status", self.session_id)),
                &[("X-Session-Signature", &session_signature)],
            )
            .await?;

        if response.keygen_session_id != self.session_id
            || response.authorization_manifest.digest()? != self.authorization_manifest.digest()?
        {
            return Err(SdkError::InvalidInput(
                "Gateway changed the trusted authorization manifest".into(),
            ));
        }
        self.encrypted_roster = response.encrypted_roster;
        response
            .recipient_authorization
            .verify(&self.authorization_manifest)?;
        if self
            .recipient_authorization
            .as_ref()
            .is_some_and(|pinned| pinned != &response.recipient_authorization)
        {
            return Err(SdkError::InvalidInput(
                "Gateway changed authorized enclave recipients".into(),
            ));
        }
        let coordinator_id = response
            .recipient_authorization
            .user_enclave_assignments
            .get(&self.authorization_manifest.manifest.coordinator_user_id)
            .ok_or_else(|| {
                SdkError::InvalidInput("Missing authorized coordinator enclave".into())
            })?;
        if response
            .recipient_authorization
            .recipient_public_keys
            .get(coordinator_id)
            != Some(
                &hex::decode(&self.roster_enclave_pubkey)
                    .map_err(|_| SdkError::InvalidInput("Invalid coordinator key".into()))?,
            )
        {
            return Err(SdkError::InvalidInput(
                "Coordinator enclave differs from authorized recipient".into(),
            ));
        }
        self.recipient_authorization = Some(response.recipient_authorization);
        self.status = response.status;
        self.aggregate_key = response.aggregate_public_key;
        self.subset_aggregates = response.encrypted_subset_aggregates;
        if matches!(self.status, KeygenStatusKind::Completed) {
            self.verify_roster()?;
        }

        Ok(&self.status)
    }

    pub async fn wait_for_completion(
        &mut self,
    ) -> Result<&crate::types::AggregatePublicKey, SdkError> {
        let config = self.client.polling_config().clone();
        let mut delay = config.initial_delay;

        for attempt in 1..=config.max_attempts {
            self.refresh_status().await?;

            match self.status {
                KeygenStatusKind::Completed => {
                    if self.aggregate_key.is_some() {
                        return self.aggregate_key.as_ref().ok_or_else(|| {
                            SdkError::Keygen(KeygenError::Failed(
                                "No aggregate key available".to_string(),
                            ))
                        });
                    } else {
                        return Err(SdkError::Keygen(KeygenError::Failed(
                            "Keygen completed but no aggregate key returned".to_string(),
                        )));
                    }
                }
                KeygenStatusKind::Failed => {
                    return Err(SdkError::Keygen(KeygenError::Failed(
                        "Keygen session failed".to_string(),
                    )));
                }
                _ => {
                    if attempt >= config.max_attempts {
                        break;
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    tokio::time::sleep(delay).await;
                    #[cfg(target_arch = "wasm32")]
                    gloo_timers::future::TimeoutFuture::new(delay.as_millis() as u32).await;

                    let next_delay_ms =
                        (delay.as_millis() as f64 * config.backoff_multiplier) as u64;
                    delay = std::time::Duration::from_millis(next_delay_ms).min(config.max_delay);
                }
            }
        }

        Err(SdkError::Keygen(KeygenError::Timeout))
    }

    pub fn decrypt_aggregate_key(&self) -> Result<Vec<u8>, SdkError> {
        self.verify_roster()?;
        let encrypted_key = self.aggregate_key.as_ref().ok_or_else(|| {
            SdkError::Keygen(KeygenError::Failed(
                "No aggregate key available".to_string(),
            ))
        })?;

        self.credentials
            .decrypt(encrypted_key, "aggregate_public_key")
    }

    /// Verify every authorized slot and recompute all funding keys before use.
    pub fn verify_roster(&self) -> Result<SignedRoster, SdkError> {
        let encrypted_roster = self.encrypted_roster.as_ref().ok_or_else(|| {
            SdkError::InvalidInput(
                "Completed keygen is missing its authenticated participant roster".into(),
            )
        })?;
        let roster: SignedRoster =
            serde_json::from_slice(&self.credentials.decrypt(encrypted_roster, ROSTER_CONTEXT)?)?;
        roster.verify(&hex::decode(&self.roster_enclave_pubkey)?)?;
        roster.verify_registrations(&self.authorization_manifest)?;
        if let Some(expected) = &self.own_registration {
            let actual = roster
                .roster
                .registrations
                .get(self.client.user_id())
                .ok_or_else(|| {
                    SdkError::InvalidInput("Roster is missing this client's registration".into())
                })?;
            if serde_json::to_value(actual)? != serde_json::to_value(expected)? {
                return Err(SdkError::InvalidInput(
                    "Roster changed this client's registration or approval policy".into(),
                ));
            }
        }
        roster.roster.verify_aggregates()?;
        let expected_tweak: TaprootTweak = serde_json::from_slice(&self.credentials.decrypt(
            &self.authorization_manifest.manifest.encrypted_taproot_tweak,
            "taproot_tweak",
        )?)?;
        if serde_json::to_vec(&expected_tweak)? != serde_json::to_vec(&roster.roster.taproot_tweak)?
        {
            return Err(SdkError::InvalidInput(
                "Roster changed the authorized taproot tweak".into(),
            ));
        }
        let aggregate = self.aggregate_key.as_ref().ok_or_else(|| {
            SdkError::InvalidInput("Completed keygen is missing its aggregate key".into())
        })?;
        if self
            .credentials
            .decrypt(aggregate, "aggregate_public_key")?
            != roster.roster.aggregate_public_key
            || self.subset_aggregates.len() != roster.roster.subset_aggregate_keys.len()
        {
            return Err(SdkError::InvalidInput(
                "Returned funding keys do not match the authenticated roster".into(),
            ));
        }
        for (subset_id, expected) in &roster.roster.subset_aggregate_keys {
            let encrypted = self.subset_aggregates.get(subset_id).ok_or_else(|| {
                SdkError::InvalidInput("Returned subset aggregate is missing".into())
            })?;
            if &self
                .credentials
                .decrypt(encrypted, SUBSET_AGGREGATE_CONTEXT)?
                != expected
            {
                return Err(SdkError::InvalidInput(
                    "Returned subset key does not match the authenticated roster".into(),
                ));
            }
        }
        if let Some(credentials) = self.client.credentials() {
            if let Some(key) = roster.roster.participants.get(self.client.user_id()) {
                let actual = roster
                    .roster
                    .registrations
                    .get(self.client.user_id())
                    .ok_or_else(|| {
                        SdkError::InvalidInput(
                            "Roster is missing this client's authorization".into(),
                        )
                    })?;
                if key != &credentials.public_key_bytes()
                    || actual.context.auth_pubkey
                        != credentials.derive_session_auth_pubkey(&self.session_id.to_string())?
                {
                    return Err(SdkError::InvalidInput(
                        "The participant roster does not contain this client's key in its slot"
                            .into(),
                    ));
                }
            }
        }
        Ok(roster)
    }

    pub fn subset_aggregate(&self, subset_id: &Uuid) -> Option<&String> {
        self.subset_aggregates.get(subset_id)
    }

    pub fn decrypt_subset_aggregate(&self, subset_id: &Uuid) -> Result<Vec<u8>, SdkError> {
        self.verify_roster()?;
        let encrypted_key = self.subset_aggregates.get(subset_id).ok_or_else(|| {
            SdkError::Keygen(KeygenError::Failed(format!(
                "Subset {} not found",
                subset_id
            )))
        })?;

        self.credentials
            .decrypt(encrypted_key, SUBSET_AGGREGATE_CONTEXT)
    }

    pub fn export_session_secret(&self) -> [u8; 32] {
        self.credentials.export_session_secret()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeygenSessionData {
    coordinator_pubkey: Vec<u8>,
    aggregate_pubkey: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeygenParticipantSessionData {
    participant_public_keys: BTreeMap<UserId, Vec<u8>>,
}
