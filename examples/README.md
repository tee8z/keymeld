# KeyMeld Examples

End-to-end examples demonstrating MuSig2 Bitcoin signing with KeyMeld.

## Quick Start

```bash
# Regular MuSig2
just quickstart

# Adaptor signatures
just quickstart-adaptors

# Batch signing
just test-batch-signing

# DLC batch signing with subset keys
just test-dlctix-batch
```

## Examples

### Regular MuSig2 (`keymeld_example`)

Complete 2-phase workflow: keygen + signing with taproot integration.

```bash
just demo 50000 bcrt1q...  # amount and destination
```

### Adaptor Signatures (`keymeld_adaptor`)

All adaptor types: Single, And, Or.

```bash
just demo-adaptors  # All types
```

### Batch Signing (`batch_signing`)

Sign multiple messages in a single session with per-item configuration.

```bash
just test-batch-signing
```

### DLC Batch Signing (`dlctix_batch`)

Complete DLC workflow demonstrating:
- **Subset definitions per outcome**: market_maker + ALL winners for that outcome
- **Weighted payouts**: Multiple winners per outcome with proportional splits
- **Mixed batch signing**: Outcome txs (n-of-n with adaptors) + split txs (k-of-k subsets)
- **Oracle attestation**: Secret recovery from adaptor signatures
- **Full payout flow**: Fund → outcome tx → split txs (one per winner)

```bash
just test-dlctix-batch
```

Key features:
- 3 players + 1 market maker (4-of-4 for outcome transactions)
- 3 outcomes with weighted payouts (60/40, 50/50, 50/30/20 splits)
- 7 split transactions total (2+2+3 winners across outcomes)
- Per-outcome subset keys for split transactions (k-of-k where k = winners + market_maker)
- Single batch signing session for all 10 transactions

## Workflow

1. **Setup**: Load/generate participant keys, fund coordinator wallet
2. **Keygen**: Reserve session, initialize with ECIES-encrypted keys, register participants
3. **Funding**: Send to aggregate key address
4. **Signing**: Create session, wait for approvals (if required), get signature
5. **Broadcast**: Apply signature to PSBT, broadcast transaction

## Transaction Patterns

### Single-Input Pattern

MuSig2 transactions typically follow a **two-transaction pattern**:

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

Benefits:
- One signing ceremony instead of one per input
- Lower coordination overhead
- Cleaner transaction structure

### DLC Pattern with Subsets

For DLCs, use subset signing for efficient 2-of-n payouts:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Funding TX                                   │
│  Output: n-of-n aggregate key (all players + market maker)          │
└─────────────────────────────────────────────────────────────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
   ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
   │   Outcome TX 0   │  │   Outcome TX 1   │  │   Outcome TX 2   │
   │ (n-of-n adaptor) │  │ (n-of-n adaptor) │  │ (n-of-n adaptor) │
   │  locked to oracle│  │  locked to oracle│  │  locked to oracle│
   └──────────────────┘  └──────────────────┘  └──────────────────┘
              │                     │                     │
              ▼                     ▼                     ▼
   ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
   │    Split TX 0    │  │    Split TX 1    │  │    Split TX 2    │
   │ outputs per win- │  │ outputs per win- │  │ outputs per win- │
   │ ning player with │  │ ning player with │  │ ning player with │
   │ weighted payouts │  │ weighted payouts │  │ weighted payouts │
   └──────────────────┘  └──────────────────┘  └──────────────────┘
              │                     │                     │
    ┌─────────┴─────────┐          ...                   ...
    ▼                   ▼
┌────────┐         ┌────────┐
│Player A│         │Player B│   Each winning player has their own
│ output │         │ output │   2-of-2 (player + MM) spending path
│(2-of-2)│         │(2-of-2)│   with weight-proportional payout
└────────┘         └────────┘
```

Each `WinCondition` = (outcome, player_index) gets its own subset signature.
When multiple players win an outcome with weighted payouts, each gets a separate
output in the split transaction, each requiring a 2-of-2 signature with the market maker.

Benefits:
- Batch sign all transactions in one session
- Subset keys for efficient 2-of-2 split payouts
- Oracle attestation unlocks winning outcome
- Weighted payouts via multiple outputs per split tx

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
