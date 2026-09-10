# Adaptor Signatures

The proposed `0.4.0` protocol supports single-point adaptor signatures for conditional payments and Discreet Log Contracts (DLCs).
`And` and `Or` configurations are unsupported and rejected.
These changes are unreleased. KeyMeld remains experimental and must not be used with real funds.

## Overview

Adaptor signatures bind MuSig2 signatures to cryptographic secrets:
- **Adaptor Point (T)**: `T = t*G` where `t` is the secret
- **Adapted Signature**: Regular signature encrypted with the adaptor point
- **Secret Recovery**: When the final signature is broadcast, secret `t` can be recovered

Use cases:
- **DLCs (Discreet Log Contracts)**: Outcome transactions locked to oracle attestation
- **Atomic Swaps**: Cross-chain exchanges without trusted intermediaries
- **Conditional Payments**: Release funds only when a secret is revealed

## Adaptor Types

### Single

Each configuration requires exactly one valid compressed secp256k1 point.
Each configuration's `adaptor_id` must be unique within its batch item.
An adaptor batch item must contain at least one configuration.

```json
{
  "adaptor_type": "Single",
  "adaptor_points": ["02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"]
}
```

### Unsupported configurations

The `And` and `Or` enum values remain decodable so unsupported requests can receive explicit errors.
Validation rejects both types before nonce generation or signing.
The SDK also rejects them before encrypting a signing request.

Earlier builds used only the first point while advertising multiple-secret conditions.
Do not rely on signatures from those builds to enforce an `And` or `Or` policy.
Changing a configuration's label to `Single` does not preserve its intended multiple-secret condition.

Optional `Single` hints remain metadata and receive format validation.
Hints do not add conditions to signature adaptation.

## API Usage

### Create Signing Session with Adaptors

Adaptor configurations are specified per batch item, allowing mixed regular and adaptor signatures in a single session.
The request below illustrates the batch payload.
Use the SDK to attach the required signing authorization and transport signature described in [authorization](AUTHORIZATION.md).

```json
POST /api/v1/signing
{
  "signing_session_id": "uuid-v7",
  "keygen_session_id": "uuid-v7",
  "timeout_secs": 1800,
  "batch_items": [
    {
      "batch_item_id": "uuid-v7",
      "message_hash": [32 bytes],
      "signing_mode": {
        "type": "adaptor",
        "encrypted_message": "hex-session-encrypted",
        "encrypted_adaptor_configs": "hex-session-encrypted-json"
      },
      "encrypted_taproot_tweak": "hex-session-encrypted",
      "subset_id": null
    }
  ]
}
```

**Adaptor Config Structure** (encrypted with session secret):
```json
[
  {
    "adaptor_id": "uuid-v7",
    "adaptor_type": "Single",
    "adaptor_points": ["02...hex-pubkey"],
    "hints": null
  }
]
```

### Status Response

```json
GET /api/v1/signing/{id}/status/{user_id}
{
  "status": "completed",
  "batch_results": [
    {
      "batch_item_id": "uuid-v7",
      "signature": "hex-encrypted",
      "adaptor_signatures": {"adaptor_id": {...}},
      "error": null
    }
  ]
}
```

Decrypt adaptor signatures client-side using session secret. Each adaptor result contains:

- `signature_scalar`: The 65-byte serialized adaptor signature
- `adaptor_points`: The single configured point
- `aggregate_adaptor_point`: The same point used by signature construction

## Privacy

- Gateway never sees adaptor IDs, business logic, or contract details
- All adaptor configurations encrypted client-side
- Each session uses unique encryption keys

## Demo Commands

```bash
just demo-adaptors       # Single-point adaptor signatures demo
just test-dlctix-batch   # DLC batch signing with adaptor + subset signing
```

## DLC Example

The `dlctix_batch` example demonstrates a complete DLC workflow:

1. **Keygen with subsets**: Define 2-of-2 subsets for each player + market_maker pair
2. **Batch signing**: Sign outcome txs (n-of-n with adaptors) and split txs (2-of-2 subsets) in one session
3. **Oracle attestation**: Oracle reveals the secret, unlocking the adaptor signature
4. **Payout**: Broadcast outcome tx, then split tx for winner

`DlcBatchBuilder` converts each oracle outcome's adaptor point into `AdaptorConfig::single()`.
The coordinator uses this builder, so rejecting `And` and `Or` does not change its current DLC construction.

```rust
// Outcome transactions use adaptor signatures locked to oracle attestation
let adaptor_config = AdaptorConfig {
    adaptor_id: Uuid::now_v7(),
    adaptor_type: AdaptorType::Single,
    adaptor_points: vec![hex::encode(locking_point)],
    hints: None,
};

SigningBatchItem {
    signing_mode: SigningMode::Adaptor { encrypted_message, encrypted_adaptor_configs },
    subset_id: None,  // n-of-n signing
    ...
}

// Split transactions use regular signatures with subset aggregate keys
SigningBatchItem {
    signing_mode: SigningMode::Regular { encrypted_message },
    subset_id: Some(outcome_subset_id),  // k-of-k signing (winners + market_maker)
    ...
}
```

See `examples/src/dlctix_batch.rs` for the complete implementation.
