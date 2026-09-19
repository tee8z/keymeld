# Payout preimage escrow

An enclave that holds a participant's key can also hold a secret the
participant would otherwise have to hand over in exchange for a payment:
a *payout preimage*, derived from the participant's key. The enclave
releases that preimage to a claimant only against proof that the claimant
paid the participant's registered Lightning Address the amount a
settlement rule says is owed. Neither side has to trust the other: the
participant never gives the preimage away for free, and the claimant can
obtain it only by paying.

This is a generic exchange. Anything that pays participants off-chain and
needs a secret from them in return can use it; the first settlement rule
implemented is a ticketed DLC contract (see below), but the rule is the
only DLC-specific part.

## Roles

- **Participant.** Registers a key with a `PayoutPolicy`: the Lightning
  Address (LUD-16) they are paid at and the node that issues invoices for
  it. Their payout preimage is `derive_payout_preimage(key)`, a tagged
  hash of the key, so the enclave stores nothing new and can reproduce it
  after a restore.
- **Claimant.** The keygen session's signing authority. Pays the address
  over LNURL-pay, then presents the paid invoice and its preimage to claim
  the payout preimage. Not trusted by the enclave.
- **Enclave.** Holds the key and policy, checks the claim, and returns the
  preimage encrypted to the session secret.

## Registration

`RegistrationEnvelope::with_payout_policy` seals the policy next to the
participant's private key. The possession signature covers
`(context, payout_policy)`, so nobody relaying the envelope can change
where a participant is paid. `keymeld-sdk`'s
`prepare_registration_with_policy` exposes it.

A claimant pays the sealed address before the enclave releases anything,
so it must know what was sealed. It states the policy it expects in
`RegisterKeygenParticipantRequest.payout_policy`; the enclave's
registration validation rejects the envelope if the sealed policy differs
(or is missing), and validates the policy's shape. A registration that
succeeds with an expected policy therefore guarantees a later claim will
not fail on the address or payee.

## Claim

`POST /keygen/{keygen_session_id}/payout-release` with a `PayoutReleaseRequest`
(`X-Session-Signature` required). The `PayoutClaim` is self-contained; the
gateway only routes it to the enclave holding the participant:

| Field | Purpose |
|---|---|
| `batch_items` + `signing_authorization` | The signed batch, exactly as the authority authorized it (`SigningReceipt` from the SDK). |
| `encrypted_contract` | The settlement rule's commitment (for the DLC rule, `ContractCommitment { contract_parameters, funding_outpoint }`), encrypted to the session secret. |
| `attestation` | The oracle's attestation for the event, when the rule needs one. |
| `invoice`, `lnurl_metadata`, `payment_preimage` | The paid invoice, the LNURL metadata it commits to, and the settlement preimage. |

The claim is signed by the keygen authority (`PayoutReleaseAuthorization`),
and only a `Completed` keygen session releases anything.

## What the enclave checks

1. The authority signed both the claim and the batch (manifest signing key).
2. **Settlement rule.** The claimed commitment is the one the participant's
   key actually signed, and it says the participant is owed a definite
   amount. For the DLC rule this means: rebuilding the `TicketedDLC` from
   the commitment yields exactly the set of sighashes that were signed;
   `attestation * G` is one of the contract's locking points; and that
   outcome's payout map pays the participant's key
   `funding_value * weight / 100`.
3. **Payment.** `sha256(payment_preimage)` is the invoice's payment hash;
   the invoice is for at least the owed amount; its description hash is
   `sha256(lnurl_metadata)` (LUD-06); the metadata's
   `text/identifier`/`text/email` names the registered address; and the
   invoice's recovered payee key is the registered `payee_node_id`.

Only then is `derive_payout_preimage(private_key)` returned, encrypted with
the session secret (`payout_preimage` context).

## Why the payee key matters

An invoice with the right description hash and a known preimage is trivial to
forge for anyone running a node, including the claimant. The invoice's
signature is what proves it came from the participant's provider, so the
policy pins the provider's node key. The participant learns it by fetching
a probe invoice from the provider directly (LNURL endpoints generally
expose CORS) before sealing the policy. Providers that rotate issuing
nodes make the claim fail closed; the claimant then falls back to whatever
trusted path it has.

## What it does not do

- The enclave cannot observe the Lightning network; "paid" means "holds the
  preimage of an invoice signed by the pinned node". A provider colluding
  with the claimant could hand out preimages; the participant chose the
  provider.
- Nothing here changes the settlement rule's own enforcement. For a DLC, a
  participant who is not paid still has their on-chain spending paths.

## Adding a settlement rule

The DLC rule lives in `keymeld_core::payout` behind the `payout` feature.
A new rule needs a commitment type the claimant encrypts to the session
secret, a way to check that the signed batch is exactly what the rule
commits to, and a function from (commitment, evidence, participant key) to
the amount owed; the payment proof and the release itself are shared.
