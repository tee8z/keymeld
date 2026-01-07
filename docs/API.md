# KeyMeld API Reference

## Endpoints

### Keygen (Phase 1)

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /api/v1/keygen/reserve` | None | Reserve keygen session, get assigned enclave |
| `POST /api/v1/keygen/{session_id}/initialize` | None | Initialize session with encrypted coordinator data |
| `GET /api/v1/keygen/{keygen_session_id}/slots` | None | Get available participant slots |
| `POST /api/v1/keygen/{keygen_session_id}/participants` | X-Session-Signature | Register participant |
| `GET /api/v1/keygen/{keygen_session_id}/status` | X-Session-Signature | Check keygen progress |

### Signing (Phase 2)

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /api/v1/signing` | X-Session-Signature | Create signing session |
| `POST /api/v1/signing/{signing_session_id}/approve/{user_id}` | X-User-Signature | Approve signing (if required) |
| `GET /api/v1/signing/{signing_session_id}/status/{user_id}` | X-User-Signature | Check signing progress |

### Utility

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /api/v1/enclaves` | None | List all enclaves |
| `GET /api/v1/enclaves/{enclave_id}/public-key` | None | Get enclave public key for ECIES |
| `GET /api/v1/health` | None | Health check |
| `GET /api/v1/version` | None | API version info |

## Keygen Workflow

### 1. Reserve Session

```
POST /api/v1/keygen/reserve
{
  "keygen_session_id": "uuid-v7",
  "coordinator_user_id": "uuid-v7",
  "expected_participants": ["user1", "user2", "user3"],
  "timeout_secs": 3600,
  "encrypted_taproot_tweak": "hex-encrypted-tweak"
}
```

Response includes `coordinator_enclave_id` and `coordinator_public_key` for ECIES encryption.

### 2. Initialize Session

```
POST /api/v1/keygen/{session_id}/initialize
{
  "coordinator_pubkey": [bytes],
  "coordinator_encrypted_private_key": "hex-ecies-encrypted",
  "session_public_key": [bytes],
  "encrypted_session_secret": "hex-ecies-encrypted",
  "encrypted_session_data": "hex-session-key-encrypted",
  "encrypted_enclave_data": "hex-ecies-encrypted",
  "enclave_key_epoch": 1
}
```

### 3. Get Available Slots

```
GET /api/v1/keygen/{keygen_session_id}/slots
```

Returns slots with `user_id`, `enclave_id`, and `signer_index` for each participant.

### 4. Register Participants

```
POST /api/v1/keygen/{keygen_session_id}/participants
X-Session-Signature: nonce:signature

{
  "keygen_session_id": "uuid-v7",
  "user_id": "uuid-v7",
  "encrypted_private_key": "hex-ecies-encrypted",
  "public_key": [bytes],
  "encrypted_session_data": "hex-session-key-encrypted",
  "enclave_public_key": "hex-pubkey",
  "enclave_key_epoch": 1,
  "require_signing_approval": false,
  "auth_pubkey": [bytes]
}
```

## Signing Workflow

### 1. Create Signing Session

```
POST /api/v1/signing
X-Session-Signature: nonce:signature

{
  "signing_session_id": "uuid-v7",
  "keygen_session_id": "uuid-v7",
  "message_hash": [32 bytes],
  "encrypted_message": "hex-optional",
  "timeout_secs": 1800,
  "encrypted_adaptor_configs": "hex-optional"
}
```

### 2. Approve (if required)

```
POST /api/v1/signing/{signing_session_id}/approve/{user_id}
X-User-Signature: nonce:signature
```

### 3. Poll Status

```
GET /api/v1/signing/{signing_session_id}/status/{user_id}
X-User-Signature: nonce:signature
```

Response includes `final_signature` when complete.

## Authentication

### X-Session-Signature

Format: `nonce:signature`
- `nonce`: Random 16-byte hex value
- `signature`: ECDSA over `SHA256(session_id:nonce)` using session-derived key

### X-User-Signature

Format: `nonce:signature`
- `nonce`: Random 16-byte hex value
- `signature`: ECDSA over `signing_session_id:user_id:nonce` using session auth key

Auth key derived via: `HKDF-SHA256(master_private_key, "keymeld-session-auth-v1:keygen_session_id")`

## Encryption

### ECIES (to enclaves)
Private keys encrypted to enclave public keys using ECIES.

### Session Key (between participants)
Session data encrypted with symmetric key derived from shared session secret.

## Taproot Configuration

```json
{"type": "none"}
{"type": "unspendable_taproot"}
{"type": "taproot_with_merkle_root", "merkle_root": "hex"}
{"type": "plain_tweak", "tweak": "hex"}
```
