# KeyMeld API Reference

## Endpoints

### Keygen (Phase 1)

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /api/v1/keygen/reserve` | Creator-signed manifest | Reserve immutable participant slots |
| `POST /api/v1/keygen/{session_id}/initialize` | Creator authorization | Initialize the reserved session |
| `GET /api/v1/keygen/{keygen_session_id}/slots` | X-Session-Signature | Get participant slots |
| `POST /api/v1/keygen/{keygen_session_id}/participants` | Slot authorization and key possession proof | Register the authorized participant |
| `GET /api/v1/keygen/{keygen_session_id}/status` | X-Session-Signature | Check keygen progress |

### Signing (Phase 2)

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /api/v1/signing` | Session header and complete-batch signing authorization | Create signing session |
| `POST /api/v1/signing/{signing_session_id}/approve/{user_id}` | User header and complete-batch participant proof | Approve the reviewed batch |
| `GET /api/v1/signing/{signing_session_id}/status/{user_id}` | X-User-Signature | Check signing progress |

### Single-Signer Key Management

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /api/v1/keys/reserve` | X-User-Signature over request scope | Reserve a slot with an immutable authentication key |
| `POST /api/v1/keys/import` | X-User-Signature | Import encrypted private key (validates auth_pubkey ownership) |
| `GET /api/v1/keys/{user_id}?key_id=...` | X-User-Signature | List keys with the authenticated key's credential |
| `GET /api/v1/keys/{user_id}/{key_id}/status` | X-User-Signature | Check key import/store status |
| `DELETE /api/v1/keys/{user_id}/{key_id}` | X-User-Signature | Delete a key |
| `POST /api/v1/keys/{user_id}/keygen/{session_id}` | Participant X-User-Signature over request scope | Store key from completed keygen |

### Single-Signer Signing

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /api/v1/sign/single` | X-User-Signature | Create single-signer signing session |
| `GET /api/v1/sign/single/{session_id}/status/{user_id}` | X-User-Signature | Check signing status |

### Utility

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /api/v1/enclaves` | None | List all enclaves |
| `GET /api/v1/enclaves/{enclave_id}/public-key?nonce={64-hex-characters}` | None | Get a key with fresh, challenge-bound attestation |
| `GET /api/v1/health` | None | Health check |
| `GET /api/v1/health/detail` | None | Detailed health check with enclave status |
| `GET /api/v1/version` | None | API version info |
| `GET /api/v1/metrics` | None | Prometheus metrics |
| `GET /api/v1/openapi.json` | None | OpenAPI specification |
| `GET /api/v1/docs` | None | Interactive API documentation (Scalar) |

## Keygen workflow

Use the SDK to construct authorization commitments and encryption envelopes.
The generated specification at `/api/v1/openapi.json` describes the exact request fields.
See [authorization](AUTHORIZATION.md) and [security configuration](SECURITY_OPERATIONS.md) before integrating custody operations.

1. Configure trusted enclave measurements on `KeyMeldClient::builder().attestation_policy(policy)`.
2. Reserve with a creator-signed manifest containing immutable participant registration verifiers.
3. Verify fresh attestation for every assigned enclave recipient.
4. Initialize with the creator's initialization signature and `EnclaveRecipientAuthorization`.
5. Deliver each participant's trusted manifest, slot credential, and shared session credentials through the application.
6. Read slots with a fresh `X-Session-Signature` header.
7. Register the contextual ECIES possession envelope with its separate slot authorization.
8. Verify the signed roster and aggregate keys before funding.

Initialization does not upload a raw coordinator private key.
The coordinator claims its participant slot through the same authorized registration flow.
The creator's recipient proof binds every participant assignment and enclave encryption key.
The enclave verifies that proof before distributing the shared session secret.

Slots cannot be replaced after a different registration claims them.
Registrations require the collecting state; exact retries are accepted only while that state remains active.
The slots response includes claimed slots for restoration. Check each slot's `claimed` flag before offering it.

## Signing workflow

All signing requests contain an ordered batch; a single message is a batch of one.
Use `SigningOptions` and `BatchSigningItem` to construct that batch through the SDK.

The request includes `SigningAuthorization` from the manifest's separate signing authority.
It commits to both session IDs, timeout, and every encrypted message, adaptor configuration, tweak, and subset identifier.
A session access header alone cannot authorize signing.

For participants registered with `require_signing_approval: true`:

1. Obtain and decrypt the batch with `SigningSession::pending_batch()`.
2. Compare every item with the application's intended transaction or contract.
3. Submit `approve(&expected_items)` with the independently reviewed items.

Approval requires a `ParticipantApproval` body and the user's fresh transport header.
The participant proof commits to the whole batch, session IDs, participant ID, and timestamp.
The enclave independently verifies the proof before signing.

Poll the signing status with the participant's `X-User-Signature` header.
Completed status retains the batch and encrypted results so the SDK can detect substituted requests.
The application must verify the resulting signature against the intended message and aggregate key.

Only the supported `Single` adaptor configuration is accepted.
`And`, `Or`, invalid points, and duplicate adaptor identifiers are rejected before nonce generation.
See [adaptor support](ADAPTORS.md).

## Single-Signer Workflow

### 1. Reserve Key Slot

```
POST /api/v1/keys/reserve
X-User-Signature: v1:timestamp:nonce:signature

{
  "key_id": "client-generated-uuid-v7",
  "user_id": "uuid-v7",
  "auth_pubkey": [33 bytes compressed auth pubkey]
}
```

Response:
```json
{
  "key_id": "uuid-v7",
  "enclave_id": 1,
  "enclave_public_key": "02abc123...",
  "enclave_key_epoch": 1
}
```

### 2. Import Key

Derive the authentication key from the imported private key with the `single_signer_auth` context.
Use this credential to reserve the slot and authorize the import.
Verify the assigned enclave's attestation before encrypting the private key with ECIES.

The gateway pins the reservation credential. The enclave derives and verifies that credential after decryption.
Another key cannot replace an occupied slot. A ciphertext replay cannot install an unrelated authentication credential.

```
POST /api/v1/keys/import
X-User-Signature: v1:timestamp:nonce:signature

{
  "key_id": "uuid-v7",
  "user_id": "uuid-v7",
  "encrypted_private_key": "hex-ecies-encrypted",
  "auth_pubkey": [33 bytes compressed auth pubkey],
  "enclave_public_key": "02abc123..."
}
```

### 3. Check Key Status

```
GET /api/v1/keys/{user_id}/{key_id}/status
X-User-Signature: v1:timestamp:nonce:signature
```

Response:
```json
{
  "key_id": "uuid-v7",
  "user_id": "uuid-v7",
  "enclave_id": 1,
  "status": "completed",
  "error_message": null
}
```

Statuses: `pending`, `processing`, `completed`, `failed`

### 4. List User Keys

```
GET /api/v1/keys/{user_id}?key_id={key_id_for_auth}
X-User-Signature: v1:timestamp:nonce:signature
```

The response includes keys with the same authentication credential as `key_id_for_auth`.
The `user_id` value is an application label; it does not establish ownership of other keys.

### 5. Create Single Signing Session

```
POST /api/v1/sign/single
X-User-Signature: v1:timestamp:nonce:signature

{
  "user_id": "uuid-v7",
  "key_id": "uuid-v7",
  "encrypted_message": "hex-session-encrypted",
  "signature_type": "schnorr_bip340",
  "encrypted_session_secret": "hex-ecies-encrypted",
  "approval_signature": "hex-ecdsa-sig",
  "approval_timestamp": 1234567890
}
```

Signature types: `ecdsa`, `schnorr_bip340`

### 6. Check Signing Status

```
GET /api/v1/sign/single/{session_id}/status/{user_id}
X-User-Signature: v1:timestamp:nonce:signature
```

Response when complete:
```json
{
  "signing_session_id": "uuid-v7",
  "user_id": "uuid-v7",
  "key_id": "uuid-v7",
  "status": "completed",
  "encrypted_signature": "hex-session-encrypted",
  "signature_type": "schnorr_bip340"
}
```

Statuses: `pending`, `processing`, `completed`, `failed`

### 7. Store Key from Keygen

Store a key from a completed MuSig2 keygen session for later single-signer use:

```
POST /api/v1/keys/{user_id}/keygen/{keygen_session_id}
X-User-Signature: v1:timestamp:nonce:signature

{
  "key_id": "uuid-v7"
}
```

Use the participant authentication key derived for the source keygen session.
The proof binds the user, source session, and destination key ID. The enclave verifies the forwarded proof before persistence.
Copied keys retain this authentication context for status, signing, and deletion requests.

### 8. Delete Key

```
DELETE /api/v1/keys/{user_id}/{key_id}
X-User-Signature: v1:timestamp:nonce:signature
```

## Authentication

### Single-key operation scopes

The SDK request types provide `auth_scope()` for reserve, import, and signing requests.
These scopes commit to the complete serialized request with distinct operation domains.
Use `StoreKeyFromKeygenRequest::auth_scope(user_id, keygen_session_id)` for persistence.
Use `keymeld_core::request_auth::delete_key_scope(key_id)` for deletion.

Sign these scopes with `UserCredentials::sign_user_request` for imported keys.
For copied keys, use `sign_for_session` with the original keygen session ID.
Read requests use the key ID as their scope. Read proofs cannot authorize writes.

### Operator UI

The admin pages and HTMX fragments are disabled by default.
Set `KEYMELD_OPERATOR_TOKEN_FILE` to a file containing 64 random hexadecimal characters to enable them.
Supply that token in `Authorization: Bearer <token>` for every UI request.
Use a trusted access proxy to authenticate operators and add this header for browser requests.
Use TLS between the operator and the trusted proxy, and protect the proxy-to-gateway connection.
The gateway returns `401` for absent or incorrect operator credentials and disables caching of authorized responses.

`just test-ui-e2e` creates an isolated operator token for the gateway and Playwright.

### Proof format and lifetime

Both authentication headers use `v1:timestamp:nonce:signature`:

- `timestamp`: Unix time in seconds, written as an unsigned decimal integer.
- `nonce`: A fresh random 16-byte value, encoded as hex.
- `signature`: A compact ECDSA signature, encoded as 128 hex characters.

The gateway rejects proofs older than 300 seconds or more than 30 seconds ahead of its clock.
It verifies each signature before consuming its nonce in SQLite.
Concurrent requests, cache eviction, and gateway restarts cannot reuse a consumed proof.
Generate a new proof for each request and retry. Legacy `nonce:signature` headers are rejected.

### X-Session-Signature

The session-derived key signs the session scope, empty user ID, timestamp, and nonce.
The commitment uses the `keymeld-http-session-auth-v1` domain.
Session access does not authorize participant registration or signing by itself.
Those operations also require their separate, body-bound authorization proofs.

### X-User-Signature

The user's authentication key signs the operation scope, user ID, timestamp, and nonce.
The commitment uses the `keymeld-http-user-auth-v1` domain.
Each domain, scope, and user ID has an unsigned 64-bit big-endian byte-length prefix.
The timestamp is an unsigned 64-bit big-endian integer. The nonce follows as 16 raw bytes.
ECDSA signs SHA-256 of this commitment.

Read scopes use the key ID or signing session ID specified by the endpoint.
Reservation, import, keygen-key storage, and single signing use their request type's `auth_scope()` commitment.
Deletion uses `keymeld-delete-user-key-v1:{key_id}`. A read proof cannot authorize deletion.

Use SDK credentials to construct these headers.
MuSig2 authentication keys derive from `HKDF-SHA256(private_key, "keymeld-session-auth-v1:{keygen_session_id}")`.
Single-signer authentication keys use `single_signer_auth` as the derivation's session ID.

## Encryption

### ECIES (to enclaves)
Private keys encrypted to enclave public keys using ECIES.

### Session Key (between participants)
Session data encrypted with symmetric key derived from shared session secret.

## Subset Signing

Subset signing enables k-of-n signing within a larger MuSig2 group. This is useful for scenarios like DLC split transactions where only a subset of participants need to sign.

### How It Works

1. **Define subsets at keygen time**: Include `subset_definitions` in the reserve request
2. **Each subset gets its own aggregate key**: Computed from BIP327-sorted participant public keys
3. **Reference subset in batch items**: Set `subset_id` on batch items that should use subset signing
4. **Automatic signer index mapping**: The enclave maps participant indices from the full group to subset-relative indices

For DLC split transactions, define each subset from the market maker and every winner for that outcome.
Use the same participant set when constructing the application's aggregate key and the KeyMeld subset definition.
The SDK recomputes and verifies returned subset aggregate keys against the authorized roster.

## Taproot Configuration

Per-item taproot tweak configuration (encrypted with session key):

```json
{"type": "none"}
{"type": "unspendable_taproot"}
{"type": "taproot_with_merkle_root", "merkle_root": "hex"}
{"type": "plain_tweak", "tweak": "hex"}
```
