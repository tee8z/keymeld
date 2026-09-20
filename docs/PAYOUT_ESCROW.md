# Coordinator payout verification

DLC payout rules have moved to application-owned Coordinator crates and its measured enclave image.
Keymeld exposes generic permissions and confidential native signing operations.
It has no payout, DLC-verifier, invoice, or LNURL gateway API.

See [Generic escrow](ESCROW.md) for Keymeld's boundary.
The Coordinator repository contains `coordinator-escrow`, `coordinator-escrow-verifier`, `coordinator-enclave`, and `coordinator-lnurl-relay`.
Its deployment and acceptance instructions live in `docs/COORDINATOR_ENCLAVE.md` and `docs/PAYOUT_ESCROW.md`.

The former `escrow-dlctix`, `escrow-lightning`, and `escrow-lnurl` build instructions are obsolete.
The existing optional SDK `dlctix` utility remains available for clients.
