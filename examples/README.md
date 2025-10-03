# KeyMeld Examples

This directory contains example implementations demonstrating how to use KeyMeld for distributed MuSig2 Bitcoin signing.

## Quick Start

### Prerequisites
- **Docker & Docker Compose**: For running enclave simulation
- **Rust 1.70+**: For building the project
- **Just**: Command runner (`cargo install just`)

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
1. Start Bitcoin Core in regtest mode
2. Launch KeyMeld gateway and 3 Nitro enclaves
3. Run the complete 2-phase MuSig2 workflow
4. Create and broadcast a real Bitcoin transaction

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

### Mutinynet Signet (Testing)
```bash
just quickstart-prod  # Uses Mutinynet signet
```

Configuration files:
- `config.yaml` - Regtest configuration
- `docker/config/example-signet.yaml` - Mutinynet configuration

## Successful Run Output

See the complete successful run logs in [success.txt](success.txt).

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
