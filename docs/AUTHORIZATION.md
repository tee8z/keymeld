# Participant and signing authorization

The `0.4.0` release separates participant registration and signing authority from the shared session secret.
See the [finding inventory](#finding-inventory) and [0.4.0 upgrade notes](releases/0.4.0.md).

## Credentials and trust

A proof of possession establishes control of a submitted key.
It does not establish entitlement to another participant's `user_id`.
Each expected participant therefore has a separate registration verifier in the session manifest.

| Material | Purpose | Expected holder |
| --- | --- | --- |
| Participant private key | Prove possession and produce MuSig2 signatures | Participant and assigned enclave |
| Shared session secret | Encrypt session data and authenticate session reads | Creator and invited participants |
| Registration credential | Authorize the exact encrypted key for one participant slot | That participant or an application acting for them |
| Creator credential | Sign the session manifest and initialization request | Session creator |
| Signing credential | Authorize the complete signing batch | Designated signing authority |
| Signed session manifest | Commit to participants, credentials, subsets, and session policy | Creator and invited participants |

The SDK creates independent registration credentials for every slot by default.
It uses one additional credential for the creator and signing roles.
The protocol permits separate keys for those two roles.

Registration credentials must differ from one another and from the creator, signing, and shared session keys.
The creator and signing keys must differ from the shared session key.
Verification compares the actual public keys, including equivalent compressed and uncompressed encodings.

Protect private authority credentials in storage and transport.
Do not derive them from the shared session secret.
The manifest and public verifiers require integrity protection; they do not require secret storage.

The creator controls which registration verifiers enter the manifest.
An application that retains registration credentials can authorize keys for those slots.
The application must bind each authorization to its own participant identity and acceptance checks.

## Session creation and registration

`SignedSessionManifest` commits to these values:

- Session ID and coordinator user ID.
- Creator, signing, and shared session public keys.
- Expected participant IDs and their registration verifiers.
- Timeout and maximum signing-session count.
- Encrypted Taproot tweak and complete subset definitions.

Clients must retain the manifest received through their trusted invitation or creation flow.
A manifest fetched from the gateway is insufficient to establish the intended creator or participant roster.

```mermaid
sequenceDiagram
    participant Creator
    participant Participant
    participant Gateway
    participant Enclave
    Creator->>Gateway: Reserve with signed manifest
    Creator->>Gateway: Initialize with creator signature
    Creator->>Participant: Trusted manifest, slot credential, shared secret
    Participant->>Gateway: Authenticated slot lookup
    Participant->>Participant: Encrypt key and contextual possession proof
    Participant->>Gateway: Register with slot authorization
    Gateway->>Enclave: Validate manifest, authorization, and envelope
    Enclave-->>Gateway: Return derived public and auth keys
    Gateway->>Gateway: Claim slot and save key atomically
    Gateway->>Enclave: Initialize authorized keygen and import registrations
    Enclave-->>Gateway: Return encrypted signed roster and aggregate keys
    Gateway-->>Participant: Return completed session
    Participant->>Participant: Verify manifest, receipts, roster, and aggregates
```

An application can retain the slot credential instead of delivering it to the participant.
The participant prepares the encrypted envelope; the application authorizes that exact envelope after its acceptance checks.

Each `RegistrationEnvelope` contains the private key, a `RegistrationContext`, and a possession signature over that context.
The context binds the session ID, manifest hash, participant ID, enclave ID, enclave key epoch, public key, auth key, and approval policy.
Elliptic Curve Integrated Encryption Scheme (ECIES) encrypts the envelope to the assigned enclave key.

`RegistrationAuthorization` signs the context and a SHA-256 hash of the decoded ciphertext bytes.
The gateway verifies this signature against the slot verifier from the pinned manifest.
The enclave decrypts the envelope and verifies the possession signature.
It derives the participant public key and session auth key from the decrypted private key, then compares them with the signed context.

The authorization signatures use versioned, domain-separated digests and typed serialization from
[keymeld-core authorization](../crates/keymeld-core/src/authorization.rs).
Use these helpers instead of implementing an independent serialization scheme.
Session and manifest binding prevent cross-session reuse; the ciphertext commitment binds the exact encrypted envelope.

The gateway requests enclave validation before it writes the registration.
The database then checks the current session state and claims the slot in one transaction.
The enclave repeats authorization checks during keygen import and restoration.

Unknown participant IDs, expired sessions, changed contexts, and incorrect enclave epochs are rejected.
Registration is allowed only while the session is `CollectingParticipants`.
Once claimed, a slot cannot accept a different registration.
An identical retry can succeed while the session still collects participants.
After that state ends, even an identical registration is rejected.

If the enclave key epoch changes before registration, prepare and authorize a new envelope.
Do not edit the epoch in an existing signed request.

`GET /api/v1/keygen/{id}/slots` requires `X-Session-Signature`.
Its `available_slots` field includes every expected slot, including claimed slots.
Filter on `claimed == false` when selecting an unclaimed slot.
Completed sessions remain readable through this endpoint for SDK restoration.

## Verify the completed roster

The coordinator enclave signs a roster containing participant keys, registration authorizations, subset definitions, the tweak, and aggregate keys.
The roster is encrypted with the shared session secret using the `authorized_participant_roster_v1` context.

`KeygenSession::verify_roster()` checks the enclave signature, pinned manifest, and every slot authorization.
It checks applicable local participant information and recomputes the full and subset aggregate keys.
It also compares returned encrypted aggregate keys with the signed roster and verifies the manifest's encrypted tweak.

`decrypt_aggregate_key()` and `decrypt_subset_aggregate()` require successful roster verification.
The subset encryption context is `subset_aggregate_public_key` on both sides.

Applications must also compare the roster with their accepted participants and expected keys.
Complete that comparison before constructing or funding a contract.
Possession of all slot credentials makes the application responsible for those identity checks.

The gateway still receives public registration context, including participant IDs, public keys, and enclave assignments.
Encrypting the returned roster does not hide metadata already present in registration requests.

The SDK verifies fresh AWS Nitro attestation before trusting enclave keys.
It checks the original COSE signature, pinned AWS certificate chain, certificate dates, PCR policy, nonce, freshness, and recipient key.
The creator signs the verified enclave recipient keys and participant assignments before initialization.
The enclave verifies this recipient proof before distributing the shared session secret.
See [security configuration](SECURITY_OPERATIONS.md) for production measurements and explicit simulation settings.

## Signing and participant approval

The shared session secret does not authorize a signing session.
`SigningAuthorization` requires the credential matching the manifest's `signing_pubkey`.
It commits to both session IDs, the timeout, and the complete ordered batch.
Each item includes its ID, encrypted message, encrypted adaptor configuration, encrypted tweak, and subset ID.
Both the gateway and enclave verify this authorization.

The participant's registration fixes `require_signing_approval`.
SDK creation and join defaults require approval.
Use `.approval(false)` explicitly for an agreed unattended workflow.
Registration inherits the selected session policy unless its options explicitly override that policy.
When this flag is false, the designated signing authority can request unattended signing.
When this flag is true, the enclave also requires that participant's valid approval.
An empty approval list cannot bypass required approvals.

Signing status includes the encrypted batch for review.
`SigningSession::pending_batch()` decrypts every item's message and signing parameters.
`approve(&expected_items)` refreshes the batch and compares it with the application's independently reviewed items.
The comparison includes item IDs and order.
Do not automatically approve the result of `pending_batch()` without application validation.

`ParticipantApproval` signs both session IDs, the participant ID, timestamp, and complete encrypted batch.
The gateway stores the proof and forwards it to the enclave.
MuSig2 approval verification rejects proofs older than 300 seconds or more than 30 seconds in the future.
Participant approvals require the auth key derived from that participant's registered private key.

These proofs bind opaque message digests and signing parameters.
The application remains responsible for deriving the intended digest from the transaction or contract being approved.

## SDK and consumer migration

Upgrade the SDK, gateway, and enclave together.
The enclave protocol advertises `authorization_protocol_version: 1`; the updated gateway requires that value.
This protocol version is separate from the package version `0.4.0`.

| Previous integration | Required integration |
| --- | --- |
| Share only session ID and secret for joining | Also deliver a trusted `ParticipantInvitation`, or authorize registration through the application |
| Initialize with arbitrary session data | Include the creator's initialization signature |
| Encrypt a raw private key for keygen registration | Call `UserCredentials::prepare_registration(context, enclave_public_key)` |
| Submit a participant with session authentication alone | Include `registration_authorization` for the exact envelope |
| Read slots without credentials | Pass `&SessionCredentials` to `get_available_slots()` |
| Restore from session ID and shared credentials | Also supply the retained `SignedSessionManifest` |
| Sign from a restored shared session | Use `restore_session_with_authority()` with the signing credential |
| Approve a session without inspecting its batch | Call `approve(&expected_items)` after independent application review |
| Accept an aggregate key immediately | Verify the signed roster and compare it with application records |

`create_session()` and `create_session_with_subsets()` still accept participant IDs before participant signing keys exist.
`KeygenOptions::participant_verifiers()` supports registration verifiers generated outside the SDK.
The SDK retains credentials only for slots it generated.

Persist the session credentials, `authorization_manifest()`, `recipient_authorization()`, `authorization_credentials()`, and necessary `registration_credentials(&user_id)` values.
Encrypt private credentials before saving them.
`AuthorizationCredentials::export_secret()` and `from_secret()` support application-managed persistence.
Protect and clear exported secret copies according to the application's secret-storage policy.

For direct registration, pass `session.invitation(&user_id)` through a confidential, authenticated participant channel.
Use `JoinOptions::default().invitation(invitation)` when joining.
Deliver the shared session secret separately or in the same protected invitation exchange.

For delegated registration, retain the slot credential in the application.
Authorize the participant's envelope only after ownership and application acceptance checks succeed.
Never issue a permanent slot credential for a reservation that can later pass to another participant.

The coordinator migration plan is tracked in its repository at `docs/KEYMELD_AUTHORIZATION_MIGRATION.md`.
It specifies encrypted credential storage, browser envelope preparation, ticket acceptance checks, and roster verification before funding.
The coordinator implementation is outside this KeyMeld change.

## Legacy sessions

Releases through `v0.3.5` lack the required authorization commitments.
Upgrade all components to 0.4.0 with fresh state.

Existing session records do not contain the mandatory manifest, registration proofs, or batch approvals.
Database migration adds storage fields; it does not manufacture trusted commitments for old sessions.
Legacy sessions fail closed under the new protocol and cannot resume through a compatibility fallback.

Legacy records can also fail bulk restoration and administrative queries during deserialization.
Do not mix legacy records with new authorized sessions in one active database.

For the upgrade:

1. Stop the gateway and enclaves before archiving their state.
2. Preserve the database and associated enclave state for audit.
3. Configure fresh state locations for the upgraded services.
4. Start matching gateway and enclave builds against the fresh state.
5. Create new sessions with fresh authorization credentials through the upgraded SDK.

Do not delete or overwrite the archived state automatically.
Database schema migration does not make in-place session restoration supported.
Do not copy an old roster into a new manifest and treat it as participant consent.

## Regression verification

Run the isolated transport suite:

```bash
nix develop -c bash examples/run-authorization-e2e.sh
```

The runner uses synthetic keys, temporary storage, three TCP enclaves, and Moto KMS.
It tests rejected registration and signing attacks, valid signatures, and recovery after gateway and enclave restarts.
It retains failure logs and performs no Bitcoin funding transactions.
Real Nitro acceptance is described in the [KMS guide](KMS.md#hardware-acceptance).

## Finding inventory

The supplied report contains ten findings from source revision `e981858`.

| Report finding | Report severity | Current disposition |
| --- | --- | --- |
| `keygen-roster-substitution` | Critical | Included: independent slot verifiers, contextual possession proofs, derived auth keys, immutable claims, and verified roster |
| `signing-approval-no-message-binding` | High | Included: independent signing authority, full-batch participant approvals, and application review API |
| `enclave-channel-unauthenticated` | Medium | Implemented: pre-provisioned gateway verifier, attested per-boot channel identity, signed requests and outcomes, replay cache, pinned KMS endpoint and key identifier, and immutable configuration |
| `adaptor-and-first-point-only` | Medium | Included: core, enclave, and SDK regressions reject unsupported `And`/`Or`, duplicate IDs, and invalid points before signing |
| `static-path-traversal` | Medium | Included: `ServeDir` replaces manual file reads; real HTTP tests reject encoded traversal and preserve asset responses |
| `unauthenticated-endpoints` | Medium | Implemented: signed creation, protected slots, operation-bound standalone key proofs, immutable reservations, enclave-derived auth keys, and credential-scoped key listings |
| `admin-ui-unauthenticated` | Low | Implemented: pages disabled by default; operator token protects all UI and fragment routes; auth public keys removed from rendered metadata |
| `approval-flow-hardening` | Low | Implemented: complete-batch proofs, bounded approval timestamps, versioned fresh transport proofs, and atomic durable replay claims |
| `attestation-never-verified` | Low | Implemented: AWS-root certificate and COSE verification, fresh challenges, PCR policy, fail-closed SDK custody, and creator-signed verified enclave recipients |
| `sdk-subset-aggregate-context` | Low | Included: shared subset encryption context and SDK aggregate verification |

New key and session creation accepts callers with their own valid credentials.
A `user_id` is an application label, not a global account identity.
Applications must enforce their own identity checks and durable quotas.
The gateway's [admission limits](SECURITY_OPERATIONS.md#limit-api-admission-and-browser-origins) bound request rates per process.

## Other enforced invariants

- Adaptor nonce derivation uses fresh randomness and complete session, participant, batch-item, and adaptor identities; configuration indices cannot wrap into reused seeds.
- Standalone import derives authentication keys from decrypted private keys; copied keygen keys retain their original authentication context after recovery.
- Creator-signed, attestation-verified recipient assignments bind session-secret distribution before encryption to other enclaves.
- Startup restores missing sessions before accepting HTTP requests and preserves already completed sessions with matching recipient proofs.
- Late registration is rejected without changing a completed keygen's participants or aggregate key.

Production KMS recovery requires the pinned key, Nitro `Recipient`, encrypted responses, and enclave-pinned AWS TLS.
See [KMS configuration](KMS.md) for policy and recovery requirements.
