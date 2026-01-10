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

### Single-Signer Key Management

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /api/v1/keys/reserve` | None | Reserve key slot, get assigned enclave |
| `POST /api/v1/keys/import` | X-User-Signature | Import encrypted private key (validates auth_pubkey ownership) |
| `GET /api/v1/keys/{user_id}?key_id=...` | X-User-Signature | List all keys for user |
| `GET /api/v1/keys/{user_id}/{key_id}/status` | X-User-Signature | Check key import/store status |
| `DELETE /api/v1/keys/{user_id}/{key_id}` | X-User-Signature | Delete a key |
| `POST /api/v1/keys/{user_id}/keygen/{session_id}` | X-Session-Signature | Store key from completed keygen |

### Single-Signer Signing

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /api/v1/sign/single` | X-User-Signature | Create single-signer signing session |
| `GET /api/v1/sign/single/{session_id}/status/{user_id}` | X-User-Signature | Check signing status |

### Utility

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /api/v1/enclaves` | None | List all enclaves |
| `GET /api/v1/enclaves/{enclave_id}/public-key` | None | Get enclave public key for ECIES |
| `GET /api/v1/health` | None | Health check |
| `GET /api/v1/health/detail` | None | Detailed health check with enclave status |
| `GET /api/v1/version` | None | API version info |
| `GET /api/v1/metrics` | None | Prometheus metrics |
| `GET /api/v1/openapi.json` | None | OpenAPI specification |
| `GET /api/v1/docs` | None | Interactive API documentation (Scalar) |

## Keygen Workflow

### 1. Reserve Session

```
POST /api/v1/keygen/reserve
{
  "keygen_session_id": "uuid-v7",
  "coordinator_user_id": "uuid-v7",
  "expected_participants": ["user1", "user2", "user3"],
  "timeout_secs": 3600,
  "encrypted_taproot_tweak": "hex-encrypted-tweak",
  "subset_definitions": [
    {
      "subset_id": "uuid-v7",
      "participants": ["user1", "user2"]
    }
  ]
}
```

Response includes `coordinator_enclave_id` and `coordinator_public_key` for ECIES encryption.

**Subset Definitions** (optional): Define participant subsets for 2-of-n signing within the larger group. Each subset gets its own aggregate key computed from BIP327-sorted participant public keys. Used for scenarios like DLC split transactions where only a subset of participants need to sign.

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

All signing requests use batch items, where a single message is simply a batch of one.

### 1. Create Signing Session

```
POST /api/v1/signing
X-Session-Signature: nonce:signature

{
  "signing_session_id": "uuid-v7",
  "keygen_session_id": "uuid-v7",
  "timeout_secs": 1800,
  "batch_items": [
    {
      "batch_item_id": "uuid-v7",
      "message_hash": [32 bytes],
      "signing_mode": { ... },
      "encrypted_taproot_tweak": "hex-session-encrypted",
      "subset_id": "uuid-v7 or null"
    }
  ]
}
```

**Batch Item Fields:**
- `batch_item_id`: UUIDv7 identifier for this item (returned in results)
- `message_hash`: 32-byte hash of the message to sign
- `signing_mode`: Specifies the signature type (see below)
- `encrypted_taproot_tweak`: Per-item taproot tweak configuration (session-key encrypted)
- `subset_id`: Optional subset ID for signing with a subset aggregate key instead of the full n-of-n key. Must reference a subset defined during keygen.

### Signing Mode

The `signing_mode` field is a tagged enum that specifies whether to produce a regular Schnorr signature or an adaptor signature:

**Regular Signature** - produces a standard Schnorr signature:
```json
{
  "type": "regular",
  "encrypted_message": "hex-session-encrypted"
}
```

**Adaptor Signature** - produces a signature locked to adaptor point(s):
```json
{
  "type": "adaptor",
  "encrypted_message": "hex-session-encrypted",
  "encrypted_adaptor_configs": "hex-encrypted-adaptor-json"
}
```

The adaptor signature can only be completed when the corresponding adaptor secret (e.g., oracle attestation) is revealed.

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

Response when complete:
```json
{
  "signing_session_id": "uuid-v7",
  "keygen_session_id": "uuid-v7",
  "status": "completed",
  "batch_results": [
    {
      "batch_item_id": "uuid-v7",
      "signature": "hex-encrypted-signature",
      "adaptor_signatures": [...],
      "error": null
    }
  ]
}
```

**Batch Result Fields:**
- `batch_item_id`: Matches the ID from the request
- `signature`: Encrypted final Schnorr signature (64 bytes when decrypted)
- `adaptor_signatures`: Optional adaptor signatures if configured
- `error`: Error message if this item failed

### Signing Statuses

| Status | Description |
|--------|-------------|
| `collecting_participants` | Waiting for all participants to join |
| `initializing_session` | Generating nonces |
| `distributing_nonces` | Collecting partial signatures |
| `finalizing_signature` | Aggregating final signatures |
| `completed` | All signatures ready in `batch_results` |
| `failed` | Session failed |

## Single-Signer Workflow

### 1. Reserve Key Slot

```
POST /api/v1/keys/reserve

{
  "user_id": "uuid-v7"
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

Generate an auth keypair and encrypt your private key to the enclave using ECIES.
The X-User-Signature proves you own the auth keypair before it's stored.

```
POST /api/v1/keys/import
X-User-Signature: nonce:signature

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
X-User-Signature: nonce:signature
```

Response:
```json
{
  "key_id": "uuid-v7",
  "user_id": "uuid-v7",
  "status": "completed",
  "error_message": null
}
```

Statuses: `pending`, `processing`, `completed`, `failed`

### 4. List User Keys

```
GET /api/v1/keys/{user_id}?key_id={key_id_for_auth}
X-User-Signature: nonce:signature
```

### 5. Create Single Signing Session

```
POST /api/v1/sign/single
X-User-Signature: nonce:signature

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

Signature types: `ecdsa`, `schnorr`

### 6. Check Signing Status

```
GET /api/v1/sign/single/{session_id}/status/{user_id}
X-User-Signature: nonce:signature
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
X-Session-Signature: nonce:signature

{
  "key_id": "uuid-v7"
}
```

### 8. Delete Key

```
DELETE /api/v1/keys/{user_id}/{key_id}
X-User-Signature: nonce:signature
```

## Authentication

### X-Session-Signature

Format: `nonce:signature`
- `nonce`: Random 16-byte hex value
- `signature`: ECDSA over `SHA256(session_id || nonce)` using session-derived key

### X-User-Signature

Format: `nonce:signature`
- `nonce`: Random 16-byte hex value  
- `signature`: ECDSA over `SHA256(scope_id || user_id || nonce)` using auth private key
- `scope_id`: The key_id being accessed (for key operations) or signing_session_id (for signing status)

Auth key derived via: `HKDF-SHA256(master_private_key, "keymeld-session-auth-v1:keygen_session_id")`

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

### Example: DLC with 3 players + 1 market maker (weighted payouts)

For DLCs with weighted payouts where multiple players can win per outcome, subsets must be defined **per-outcome** (not per-player). Each outcome's split transaction key is the aggregate of the market maker + ALL winners for that outcome.

```json
// At keygen - define subsets per outcome containing all winners + market_maker
// Outcome 0: Player 0 (60%) + Player 1 (40%)
// Outcome 1: Player 1 (50%) + Player 2 (50%)
// Outcome 2: Player 0 (50%) + Player 1 (30%) + Player 2 (20%)
{
  "subset_definitions": [
    {"subset_id": "subset-outcome-0", "participants": ["market_maker", "player_0", "player_1"]},
    {"subset_id": "subset-outcome-1", "participants": ["market_maker", "player_1", "player_2"]},
    {"subset_id": "subset-outcome-2", "participants": ["market_maker", "player_0", "player_1", "player_2"]}
  ]
}

// At signing - outcome txs use full n-of-n, split txs use per-outcome subsets
{
  "batch_items": [
    // Outcome transactions (n-of-n adaptor signatures)
    {
      "batch_item_id": "outcome-0",
      "message_hash": [...],
      "signing_mode": {"type": "adaptor", "encrypted_message": "...", "encrypted_adaptor_configs": "..."},
      "encrypted_taproot_tweak": "...",
      "subset_id": null
    },
    // ... outcome-1, outcome-2 similar
    
    // Split transactions (k-of-k per outcome - regular signatures)
    {
      "batch_item_id": "split-outcome0-player0",
      "message_hash": [...],
      "signing_mode": {"type": "regular", "encrypted_message": "..."},
      "encrypted_taproot_tweak": "...",
      "subset_id": "subset-outcome-0"
    }
    // ... other split transactions similar, each referencing its outcome's subset
  ]
}
```

**Important**: The subset for each outcome must include ALL winners for that outcome, not just individual players. This is because `dlctix` computes the split transaction's aggregate key from `market_maker + all_winners`.

## Taproot Configuration

Per-item taproot tweak configuration (encrypted with session key):

```json
{"type": "none"}
{"type": "unspendable_taproot"}
{"type": "taproot_with_merkle_root", "merkle_root": "hex"}
{"type": "plain_tweak", "tweak": "hex"}
```
