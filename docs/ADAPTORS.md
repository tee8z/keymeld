# Adaptor Signatures

KeyMeld supports adaptor signatures for atomic swaps, conditional payments, and smart contract patterns.

## Overview

Adaptor signatures bind MuSig2 signatures to cryptographic secrets:
- **Adaptor Point (T)**: `T = t*G` where `t` is the secret
- **Adapted Signature**: Regular signature encrypted with the adaptor point
- **Secret Recovery**: When signature is revealed, secret `t` can be recovered

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

```json
POST /api/v1/signing
{
  "signing_session_id": "uuid-v7",
  "keygen_session_id": "uuid-v7",
  "message_hash": [1,2,3,...],
  "encrypted_message": "hex-encoded-message",
  "timeout_secs": 1800,
  "encrypted_adaptor_configs": "hex-encoded-encrypted-json"
}
```

Client encrypts adaptor configs using session secret before sending.

### Status Response

```json
GET /api/v1/signing/{id}/status
{
  "status": "Completed",
  "final_signature": "hex-encoded-encrypted-signature",
  "adaptor_signatures": "hex-encoded-encrypted-adaptor-results"
}
```

Decrypt adaptor signatures client-side using session secret.

## Privacy

- Gateway never sees adaptor IDs, business logic, or contract details
- All adaptor configurations encrypted client-side
- Each session uses unique encryption keys

## Demo Commands

```bash
just demo-adaptors              # Test all types
just demo-adaptors-single       # Single adaptor only
just demo-adaptors-and          # And logic only
just demo-adaptors-or           # Or logic only
```
