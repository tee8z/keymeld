# KeyMeld Examples

This directory contains example implementations demonstrating how to use KeyMeld for distributed MuSig2 Bitcoin signing, including both regular MuSig2 and adaptor signatures workflows.

## Quick Start

### Prerequisites
- **Nix**: Package manager with reproducible builds
  ```bash
  curl -L https://nixos.org/nix/install | sh
  ```
- All other dependencies (Rust, Bitcoin Core, etc.) handled automatically by Nix

### Setup & Run
```bash
# Clone and navigate to project
git clone https://github.com/tee8z/keymeld.git
cd keymeld

# Run the complete end-to-end example
just quickstart

# Or run with custom parameters
just demo 50000 bcrt1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
```

The `just quickstart` command will:
1. Build KeyMeld with Nix (fast incremental compilation)
2. Start Bitcoin Core in regtest mode
3. Launch KeyMeld gateway and 3 simulated enclaves
4. Run the complete 2-phase MuSig2 workflow
5. Create and broadcast a real Bitcoin transaction

## Examples Overview

This directory contains two main examples:

### 1. Regular MuSig2 Example (`keymeld_example`)
Basic distributed MuSig2 signing with taproot integration.

```bash
# Run regular MuSig2 example (in Nix shell)
nix develop -c cargo run --bin keymeld_example -- -a 50000 -d bcrt1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

# Or use the justfile command
just demo 50000 bcrt1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
```

### 2. Adaptor Signatures Example (`keymeld_adaptor_test`)
Comprehensive adaptor signatures testing with multiple signature types.

```bash
# Test all adaptor signature types (in Nix shell)
nix develop -c cargo run --bin keymeld_adaptor_test -- -a 50000 -d bcrt1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

# Or use the justfile command
just demo-adaptors 50000 bcrt1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

# Test specific adaptor types (in Nix shell)
nix develop -c cargo run --bin keymeld_adaptor_test -- -a 50000 -d bcrt1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh --single-only
nix develop -c cargo run --bin keymeld_adaptor_test -- -a 50000 -d bcrt1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh --and-only
nix develop -c cargo run --bin keymeld_adaptor_test -- -a 50000 -d bcrt1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh --or-only
nix develop -c cargo run --bin keymeld_adaptor_test -- -a 50000 -d bcrt1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh --skip-regular-signing
```

## Shared Library Structure

The examples share common functionality through a modular structure:

- **`lib.rs`**: Core utilities, configuration loading, and `KeyMeldE2ETest` implementation
- **`adaptor_utils.rs`**: Adaptor-specific utilities for creating, validating, and displaying adaptor signatures
- **`keymeld_example.rs`**: Clean regular MuSig2 example
- **`keymeld_adaptor_test.rs`**: Comprehensive adaptor signatures testing

## Architecture Overview

KeyMeld implements distributed MuSig2 signing using AWS Nitro Enclaves. The example demonstrates a realistic Bitcoin transaction signing workflow optimized for coordination efficiency.

### Why Single-Input Transactions?

This example focuses on **single-input MuSig2 transactions** by design. Here's why:

#### Real-World Usage Pattern

In practice, MuSig2 transactions typically follow a **two-transaction pattern**:

```
┌─────────────────────────────────────┐    ┌──────────────────────────────────┐
│        Consolidation TX             │    │         MuSig2 TX               │
│  (Normal Bitcoin signatures)        │    │   (Coordinated signatures)      │
│                                     │    │                                  │
│  Input 1: UTXO A                   │    │  Input: Consolidated UTXO       │
│  Input 2: UTXO B            ───────┼────┼──→ (MuSig2 aggregate sig)      │
│  Input 3: UTXO C                   │    │                                  │
│  ...                                │    │  Output 1: Payment               │
│  Output: Consolidated UTXO          │    │  Output 2: Change                │
└─────────────────────────────────────┘    └──────────────────────────────────┘
```

**Step 1**: Consolidate multiple UTXOs into a single output using regular Bitcoin signatures
**Step 2**: Spend that single output using MuSig2 for the coordinated transaction

#### Why This Approach?

1. **Coordination Efficiency**:
   - Multi-input MuSig2 requires separate signing ceremonies for each input
   - Each ceremony involves multiple communication rounds between participants
   - Single ceremony = faster completion, less coordination overhead

2. **Reliability**:
   - Lower chance of coordination failures
   - Atomic operation - all participants complete one ceremony or none

3. **Cost Effectiveness**:
   - Fewer network round-trips between participants
   - Reduced enclave computation costs
   - Simpler session management

4. **Real-World Use Cases**:
   - **Joint Custody**: Pre-planned amounts, not random UTXO cleanup
   - **Lightning Channels**: Specific channel funding amounts
   - **Corporate Treasury**: Deliberate spending decisions with known amounts
   - **Privacy Transactions**: Clean spending patterns

5. **Privacy Benefits**:
   - Single-input transactions reveal less about UTXO management
   - Cleaner transaction structure


## Taproot-Tweaked MuSig2 Integration

### Bitcoin Compatibility
KeyMeld implements proper Bitcoin taproot integration with MuSig2:

1. **Taproot Tweak Configuration**: Configurable tweaking modes for different use cases
2. **Proper Sighash**: Implements BIP 341 taproot sighash calculation
3. **Valid Signatures**: Creates signatures that validate on Bitcoin network

### Taproot Tweak Options
```json
{
  "taproot_tweak_config": {
    "type": "none"  // Default: no tweaking
  }
}
```

Available configurations:
- `"none"` - No tweaking (default, for non-Bitcoin protocols)
- `"unspendable_taproot"` - Standard Bitcoin key-path spending
- `"taproot_with_merkle_root"` - Commit to specific tapscript tree
- `"plain_tweak"` / `"x_only_tweak"` - Custom scalar tweaks

### MuSig2 Signing Process

#### 1. Sighash Calculation
```rust
// Calculate taproot sighash for input 0 using BIP 341
let sighash = sighash_cache.taproot_key_spend_signature_hash(
    0, // input index
    &prevouts, // all previous outputs
    TapSighashType::Default // SIGHASH_ALL equivalent
)?;
```

#### 2. Session Creation
```rust
// The sighash becomes the message signed by MuSig2
let message_hash = sighash.to_vec();
```

#### 3. Signature Application
```rust
// Apply as taproot key-path signature (no sighash byte for Default)
psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[signature_bytes]));
```

## Example Workflow

The `keymeld_example.rs` demonstrates a complete end-to-end workflow:

### 1. Coordinator Setup
- Generate or load coordinator private key
- Fund coordinator wallet from Bitcoin Core
- Derive taproot address for receiving funds

### 2. Transaction Creation
- Create a Bitcoin transaction spending from coordinator's UTXO
- Validate it's a single-input transaction
- Calculate the taproot sighash for input 0

### 3. MuSig2 Session
- Create KeyMeld session with taproot tweak configuration
- Use sighash as the message to be signed by MuSig2
- Generate session secret for participant coordination
- Encrypt all sensitive data using ECIES

### 4. Participant Registration
- Coordinator registers as participant 0 (first signer)
- Additional participants register with encrypted private keys
- Each participant gets assigned to a specific enclave

### 5. Automatic Signing
- KeyMeld's session coordinator automatically advances through MuSig2 states:
  - `CollectingParticipants` → `SessionFull` → `GeneratingNonces` →
  - `CollectingNonces` → `AggregatingNonces` → `GeneratingPartialSignatures` →
  - `CollectingPartialSignatures` → `FinalizingSignature` → `Completed`

### 6. Signature Application & Broadcast
- Decrypt the final MuSig2 signature
- Apply it to the transaction input
- Finalize the PSBT and extract the signed transaction
- Broadcast to the Bitcoin network

## Configuration

The example supports multiple Bitcoin networks:

### Regtest (Development)
```bash
just quickstart  # Uses regtest with local Bitcoin Core
```

### Alternative Networks

To use other Bitcoin networks (testnet, signet, mainnet), modify the `network` field in `config/development.yaml` and update the Bitcoin RPC connection details accordingly.

Configuration files:
- `config/development.yaml` - Development configuration for regtest
- `config/production.yaml` - Production configuration template

## Successful Run Output

See the complete successful regular run logs in [regular_success.txt](regular_success.txt).
See the complete successful adaptor run logs in [adapter_success.txt](adapter_success.txt).

### Key Success Indicators
```text
✅ Keygen complete: 02ad31bb0119e87fdd6849820f66cca278b3e3980d1ca1be0a88ca83bd259b3b14
✅ Transaction broadcast successfully: 70b5248fbcba0e81218dad91b60385680ee4d7156b8853322b535b4f876ed9f7
🎉 Two-Phase KeyMeld Test Completed Successfully!
```

### What the Logs Show
- **Phase 1**: Distributed MuSig2 keygen with taproot-tweaked aggregate key
- **Phase 2**: Signing session inherits participants from keygen (no re-registration)
- **Bitcoin Integration**: Proper taproot sighash calculation and signature validation
- **End Result**: Successfully broadcast Bitcoin transaction using distributed MuSig2

### Key Technical Details
- **Taproot Addresses Match**: Same address used for funding and spending
- **Sighash Consistency**: Same sighash calculated for session creation and signature verification
- **MuSig2 Validity**: 64-byte Schnorr signature validates against Bitcoin's consensus rules
- **Enclave Security**: All private keys remain encrypted and isolated in enclaves
