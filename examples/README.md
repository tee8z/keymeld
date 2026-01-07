# KeyMeld Examples

End-to-end examples demonstrating MuSig2 Bitcoin signing with KeyMeld.

## Quick Start

```bash
# Regular MuSig2
just quickstart

# Adaptor signatures
just quickstart-adaptors
```

## Examples

### Regular MuSig2 (`keymeld_example`)

Complete 2-phase workflow: keygen + signing with taproot integration.

```bash
just demo 50000 bcrt1q...  # amount and destination
```

### Adaptor Signatures (`keymeld_adaptor_test`)

All adaptor types: Single, And, Or.

```bash
just demo-adaptors              # All types
just demo-adaptors-single       # Single only
just demo-adaptors-and          # And logic
just demo-adaptors-or           # Or logic
```

## Workflow

1. **Setup**: Load/generate participant keys, fund coordinator wallet
2. **Keygen**: Reserve session, initialize with ECIES-encrypted keys, register participants
3. **Funding**: Send to aggregate key address
4. **Signing**: Create session, wait for approvals (if required), get signature
5. **Broadcast**: Apply signature to PSBT, broadcast transaction

## Why Single-Input Transactions?

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

Benefits:
- One signing ceremony instead of one per input
- Lower coordination overhead
- Cleaner transaction structure
- Matches real use cases (treasury, channels, escrow)

## Configuration

Edit `config/development.yaml` or pass CLI args:

```bash
cargo run --bin keymeld_example -- \
  -a 50000 \                           # amount in sats
  -d bcrt1q...                         # destination address
```

## Key Files

Keys are stored in `data/keys/`:
- `coordinator.key` - Coordinator mnemonic
- `participant_N.key` - Participant mnemonics

Delete to regenerate.

## Success Output

```
✅ Keygen complete: 02ad31bb...
✅ Transaction broadcast: 70b5248f...
```

See `regular_success.txt` and `adapter_success.txt` for full logs.
