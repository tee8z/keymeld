# KeyMeld Architecture

## Overview

KeyMeld is a distributed MuSig2 signing system using AWS Nitro Enclaves for key operations.
For the 0.4.0 authorization proofs and complete request flow, see [participant and signing authorization](AUTHORIZATION.md).

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│       SDK       │────▶│    Gateway      │────▶│    Enclaves     │
│  (Coordinator   │     │  (REST API +    │     │  (MuSig2 ops    │
│  + Participants)│     │   Coordinator)  │     │   in isolation) │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌─────────────────┐
                        │    SQLite DB    │
                        │  (encrypted     │
                        │   session data) │
                        └─────────────────┘
```

## Components

### Gateway
- REST API for session management
- Session coordinator (background task advancing MuSig2 states)
- SQLite database for encrypted session/key storage
- VSock connection pool to enclaves

### Enclaves
- Isolated environments (AWS Nitro or local simulation)
- MuSig2 operations: keygen, nonce generation, partial signatures
- ECIES decryption of private keys
- KMS integration for key persistence

### SDK
- Coordinator: Creates sessions, provides first key
- Participants: Register with encrypted keys

## 2-Phase MuSig2 Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         PHASE 1: KEYGEN                              │
└─────────────────────────────────────────────────────────────────────┘

  Coordinator                    Gateway                      Enclaves
      │                            │                              │
      │  POST /keygen/reserve      │                              │
      │  (user_ids, timeout)       │                              │
      │───────────────────────────▶│                              │
      │                            │                              │
      │  {coordinator_enclave_id,  │                              │
      │   coordinator_public_key}  │                              │
      │◀───────────────────────────│                              │
      │                            │                              │
      │  POST /keygen/{id}/init    │                              │
      │  (ECIES session secret)    │                              │
      │───────────────────────────▶│  Initialize keygen           │
      │                            │─────────────────────────────▶│
      │                            │                              │
      │  Participants register     │                              │
      │  POST /keygen/{id}/participants                           │
      │───────────────────────────▶│  Distribute to enclaves      │
      │                            │─────────────────────────────▶│
      │                            │                              │
      │                            │  Generate aggregate key      │
      │                            │◀─────────────────────────────│
      │                            │                              │
      │  GET /keygen/{id}/status   │                              │
      │───────────────────────────▶│                              │
      │  {aggregate_public_key}    │                              │
      │◀───────────────────────────│                              │

┌─────────────────────────────────────────────────────────────────────┐
│                         PHASE 2: SIGNING                             │
└─────────────────────────────────────────────────────────────────────┘

  Coordinator                    Gateway                      Enclaves
      │                            │                              │
      │  POST /signing             │                              │
      │  (keygen_id, message_hash) │                              │
      │───────────────────────────▶│                              │
      │                            │  Inherits participants       │
      │                            │  from keygen session         │
      │                            │                              │
      │                            │  [If approvals required]     │
      │  POST /signing/{id}/approve│                              │
      │───────────────────────────▶│                              │
      │                            │                              │
      │                            │  Auto-advance MuSig2:        │
      │                            │  1. Generate nonces          │
      │                            │─────────────────────────────▶│
      │                            │  2. Collect nonces           │
      │                            │◀─────────────────────────────│
      │                            │  3. Generate partial sigs    │
      │                            │─────────────────────────────▶│
      │                            │  4. Aggregate signature      │
      │                            │◀─────────────────────────────│
      │                            │                              │
      │  GET /signing/{id}/status  │                              │
      │───────────────────────────▶│                              │
      │  {final_signature}         │                              │
      │◀───────────────────────────│                              │
```

## State Machines

### Keygen States
```
Reserved ──▶ CollectingParticipants ──▶ KeyGeneration ──▶ Completed
                                                      └──▶ Failed
```

### Signing States
```
CollectingParticipants ──▶ InitializingSession ──▶ DistributingNonces
         │                                                │
         ▼                                                ▼
    [Wait for                                    FinalizingSignature
     approvals]                                           │
                                                   ┌──────┴──────┐
                                                   ▼             ▼
                                               Completed      Failed
```

## Security Model

```
┌─────────────────────────────────────────────────────────────────────┐
│                          CLIENT LAYER                                │
│                                                                      │
│  • Holds plaintext private keys                                     │
│  • ECIES encrypts keys to specific enclave public keys              │
│  • Session secret encrypts metadata between participants            │
│  • Derives session auth keys via HKDF for unlinkability             │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   │ HTTPS (encrypted payloads)
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          GATEWAY LAYER                               │
│                                                                      │
│  • Stores ECIES-encrypted private keys                              │
│  • Stores session-key-encrypted metadata (cannot decrypt)           │
│  • Coordinates session state transitions                            │
│  • Routes messages to correct enclaves                              │
│  • SQLite: encrypted payloads and metadata                          │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   │ VSock (encrypted payloads)
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          ENCLAVE LAYER                               │
│                                                                      │
│  • ECIES decrypts private keys using enclave private key            │
│  • Performs MuSig2 operations in isolated memory                    │
│  • KMS integration for key persistence across restarts              │
│  • Attestation proves enclave code integrity                        │
│  • Keys never leave enclave in plaintext                            │
└─────────────────────────────────────────────────────────────────────┘
```

## Encryption Layers

| Data | Encryption | Who Can Decrypt |
|------|-----------|-----------------|
| Private keys | ECIES to enclave pubkey | Target enclave; also a principal able to recover its KMS hierarchy |
| Session secret | ECIES to enclave pubkey | Authorized clients and enclaves; KMS recovery trust also applies |
| Session metadata | AES with session key | Participants + enclaves |
| Taproot tweak | AES with session key | Participants + enclaves |
| Adaptor configs | AES with session key | Participants + enclaves |
| Final signature | AES with session key | Participants |

## Participant Assignment

```
Reserve Request:
  expected_participants: [user_A, user_B, user_C]
  
Gateway assigns slots:
  ┌─────────────┬─────────────┬──────────────┐
  │   User ID   │  Enclave    │ Signer Index │
  ├─────────────┼─────────────┼──────────────┤
  │   user_A    │  enclave_0  │      0       │  (coordinator)
  │   user_B    │  enclave_1  │      1       │
  │   user_C    │  enclave_2  │      2       │
  └─────────────┴─────────────┴──────────────┘

Signing sessions inherit same assignments from keygen.
```

## KMS Key Persistence

KMS recovery uses IAM-authorized calls without Nitro Recipient attestation.
See the [KMS trust boundary](KMS.md#current-trust-boundary) for who can recover the stored key hierarchy.

```
First Boot:
  Enclave ──▶ Generate keypair
          ──▶ KMS.GenerateDataKey() ──▶ DEK (plaintext + encrypted)
          ──▶ AES-GCM encrypt private key with DEK
          ──▶ Store {encrypted_dek, encrypted_private_key} in DB
          ──▶ Retain DEK in enclave memory while keys are in use

Restart:
  Gateway ──▶ Load {encrypted_dek, encrypted_private_key} from DB
          ──▶ Send to enclave
  Enclave ──▶ KMS.Decrypt(encrypted_dek) ──▶ DEK
          ──▶ AES-GCM decrypt private key
          ──▶ Retain DEK in enclave memory while keys are in use
          ──▶ Resume with same keypair
```

## VSock Communication

```
Development (local simulation):
  Gateway ──▶ TCP localhost:500X ──▶ socat ──▶ Enclave process

Production (AWS Nitro):
  Gateway ──▶ VSock CID:X:500X ──▶ Nitro Enclave VM
```

Connection pool manages multiple connections per enclave with health checking and automatic reconnection.
