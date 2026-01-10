# KeyMeld

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MuSig2](https://img.shields.io/badge/MuSig2-BIP--327-green.svg)](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)

> **Not audited - use with caution**

Distributed MuSig2 Bitcoin signing via AWS Nitro Enclaves using a secure 2-phase workflow.

## Motivation

### The Challenge

MuSig2 as a protocol has two key constraints that make it difficult to use in multi-party setups:

- **Two rounds of communication**: All participants must come online and communicate in two distinct rounds to create an aggregated signature
- **Known participants**: All participant public keys must be known at the start of the process
- **Liveness requirements**: Especially challenging in mobile or distributed scenarios where participants may have unreliable connectivity or may never come back online after joining

### KeyMeld's Solution

KeyMeld addresses these challenges by delegating the coordination complexity to secure AWS Nitro Enclaves:

- **Asynchronous participation**: Participants can join sessions without requiring others to be online
- **Dynamic participant discovery**: No need to know all participants upfront
- **Reliable coordination**: Enclaves handle the two-round MuSig2 protocol automatically
- **2-phase workflow**: Separates key generation from signing for better UX

### Security Trade-offs

KeyMeld's approach involves several security trade-offs compared to purely local signing:

**Trade-off 1: Key Movement vs Convenience**
- **Risk**: Sending encrypted private keys to remote enclaves increases attack surface compared to never moving keys
- **Benefit**: Enables automated multi-party workflows without coordinating multiple devices/locations
- **Mitigation**: ECIES encryption ensures keys are never transmitted in plaintext

**Trade-off 2: Trust Model**
- **Risk**: Must trust AWS Nitro Enclave hardware and attestation process
- **Benefit**: Hardware-level isolation provides stronger guarantees than software-only solutions
- **Best for**: Organizations comfortable with cloud HSM trust models

**Trade-off 3: Operational Complexity vs Security**
- **Risk**: More complex infrastructure compared to simple local signing
- **Benefit**: Centralized coordination with distributed key custody
- **Best for**: High-frequency multi-party transactions where coordination overhead matters

### Use Cases

- **Corporate treasury management**: Multi-signature spending from company funds
- **Insurance payouts**: Multi-party approval for claim settlements
- **Escrow services**: Trustless multi-party transaction coordination
- **Bitcoin trust funds**: Trustees managing bitcoin held in trust with multi-party approval requirements

## Quick Start

```bash
# Prerequisites: Nix package manager
curl -L https://nixos.org/nix/install | sh

# Clone and run
git clone https://github.com/tee8z/keymeld.git
cd keymeld
just quickstart     # Complete setup + MuSig2 demo
```

**Other demos:**
```bash
just demo-adaptors       # Adaptor signatures demo
just test-batch-signing  # Batch signing E2E test
just test-dlctix-batch   # DLC batch signing with subset keys
just test-single-signer  # Single-signer key import demo
```

## How It Works

### 2-Phase MuSig2 Workflow

**Phase 1: Keygen** - Distributed key generation
```
CollectingParticipants → KeyGeneration → Completed (aggregate public key ready)
```

**Phase 2: Signing** - Transaction signing (inherits participants from keygen)
```
CollectingParticipants → GeneratingNonces → ... → Completed (signature ready)
```

### Architecture

```
SDK ──HTTP──▶ Gateway ──VSock──▶ Enclaves
                 │
                 ▼
              SQLite
```

- **Gateway**: REST API coordinating sessions
- **Enclaves**: Isolated MuSig2 operations with ECIES encryption
- **Database**: Encrypted session data only

> See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed diagrams and security model.

## Features

| Feature | Description |
|---------|-------------|
| **MuSig2 Signing** | BIP-327 compliant multi-party Schnorr signatures |
| **Batch Signing** | Sign multiple messages in a single session with per-item configuration |
| **Subset Signing** | Define participant subsets for 2-of-n signing within larger groups |
| **Adaptor Signatures** | Single, And, Or logic for atomic swaps and conditional payments |
| **Single-Signer Mode** | Import keys for non-MuSig signing (ECDSA & Schnorr) |
| **Taproot Support** | Flexible tweaking modes for Bitcoin compatibility |
| **Zero-Knowledge** | Gateway never sees plaintext keys or transaction data |

## Commands

```bash
# Service Management
just start              # Start all services
just stop               # Stop all services
just status             # Check service health

# Development
just build              # Build all services
just test               # Run tests
just check              # Format + lint + test
just dev                # Enter Nix dev shell

# Demo & Testing
just demo               # MuSig2 demo
just demo-adaptors      # Adaptor signatures demo
just test-batch-signing # Batch signing E2E test
just test-dlctix-batch  # DLC batch signing with subset keys
just test-single-signer # Single-signer E2E test

# AWS Deployment
just build-eif          # Build Nitro Enclave image
just deploy-aws         # Deploy to AWS
just gateway-aws        # Start gateway for AWS

just help               # Show all commands
```

## API

Interactive docs available at `http://localhost:8080/api/v1/docs` after starting the gateway.

**Keygen endpoints:**
- `POST /api/v1/keygen` - Create keygen session
- `POST /api/v1/keygen/{id}/participants` - Register participant
- `GET /api/v1/keygen/{id}/status` - Check progress

**Signing endpoints:**
- `POST /api/v1/signing` - Create signing session
- `POST /api/v1/signing/{id}/approve/{user_id}` - Approve signing
- `GET /api/v1/signing/{id}/status/{user_id}` - Check progress

> See [docs/API.md](docs/API.md) for complete API reference including single-signer endpoints.

## Documentation

| Document | Description |
|----------|-------------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, state machines, security model |
| [docs/API.md](docs/API.md) | Complete API reference |
| [docs/ADAPTORS.md](docs/ADAPTORS.md) | Adaptor signatures guide |
| [docs/SETUP.md](docs/SETUP.md) | Development environment setup |
| [docs/DEPLOY.md](docs/DEPLOY.md) | AWS Nitro Enclave deployment |
| [docs/VSOCK.md](docs/VSOCK.md) | VSock architecture |
| [docs/KMS.md](docs/KMS.md) | KMS key persistence |
| [docs/LITESTREAM.md](docs/LITESTREAM.md) | Database replication |
| [examples/README.md](examples/README.md) | Demo usage patterns |

## Project Structure

```
keymeld/
├── crates/
│   ├── keymeld-core/     # MuSig2 logic & session states
│   ├── keymeld-gateway/  # REST API & coordinator
│   ├── keymeld-enclave/  # Nitro runtime
│   └── keymeld-sdk/      # Client SDK
├── examples/             # Bitcoin demos
└── docs/                 # Documentation
```

## Resources

- [BIP-327: MuSig2](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)
- [musig2 crate](https://github.com/conduition/musig2)
- [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/)

## License

MIT
