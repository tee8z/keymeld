# Adaptor Signatures

KeyMeld supports adaptor signatures for atomic swaps, conditional payments, DLCs, and smart contract patterns.

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
One secret point required.

```json
{
  "adaptor_type": "Single",
  "adaptor_points": ["02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"]
}
```

### And
Multiple secrets required (all must be known).

```json
{
  "adaptor_type": "And",
  "adaptor_points": [
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    "03defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34"
  ]
}
```

### Or
Alternative secrets (any one works).

```json
{
  "adaptor_type": "Or",
  "adaptor_points": [
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    "03defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34"
  ],
  "hints": ["hint1", "hint2"]
}
```

## API Usage

### Create Signing Session with Adaptors

Adaptor configurations are specified per batch item, allowing mixed regular and adaptor signatures in a single session.

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
- `was_negated`: Whether the signature was negated during aggregation

## Privacy

- Gateway never sees adaptor IDs, business logic, or contract details
- All adaptor configurations encrypted client-side
- Each session uses unique encryption keys

## Demo Commands

```bash
just demo-adaptors       # Adaptor signatures demo (all types)
just test-dlctix-batch   # DLC batch signing with adaptor + subset signing
```

## DLC Example

The `dlctix_batch` example demonstrates a complete DLC workflow:

1. **Keygen with subsets**: Define 2-of-2 subsets for each player + market_maker pair
2. **Batch signing**: Sign outcome txs (n-of-n with adaptors) and split txs (2-of-2 subsets) in one session
3. **Oracle attestation**: Oracle reveals the secret, unlocking the adaptor signature
4. **Payout**: Broadcast outcome tx, then split tx for winner

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
