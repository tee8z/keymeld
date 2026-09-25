# Generic escrow

Keymeld holds participant keys and named secrets under participant-signed permissions.
The generic engine contains no DLC, invoice, Lightning Address, or application network rules.
Application-owned measured enclave images can register trusted verifiers.
The stock registry is empty.

## Permissions

A v2 policy binds its participant, keygen session, manifest, escrow identity, and application commitment.
The participant signature covers the verifier selection, exact permissions, named secret commitments, and retry rules.
The encrypted registration contains that policy, the signing key, and any deposited secrets.
Old draft signatures do not authorize v2 policies.

| Permission | Result |
| --- | --- |
| `Sign` | A permit for an exact signing scope and named signing session. |
| `SignBip340` | Plain BIP340 signatures by the participant's untweaked key over 32-byte digests, such as taproot script-path sighashes. |
| `ReleaseSecret` | One named secret encrypted to its authorized recipient. |
| `ReleaseSigningKey` | The participant key encrypted to its independently authorized recipient. |

Signing permission does not authorize either release.

`SignBip340` signs outside any MuSig2 session.
The scope names the participant's own key and lists each digest, and the output returns one signature per item.
As a late-bound permission it requires a verifier rule, so the verifier computes the digests from the transaction it authorizes.
With `VerifierAuthorizedAttempts` repetition, each fresh attempt may prepare and execute once with its own messages.
This suits protocols such as Ark, where a retried batch signs new transactions.
It also applies to a verifier-authorized `Sign`, where each attempt needs its own MuSig2 signing session.
That repetition is refused for release permissions and for exact scopes.
The ordinary keygen export bridge rejects escrow-protected keys.
Unknown versions, conditions, actions, and verifier selections fail closed.
An application commitment authenticates bytes; it does not establish their meaning.
A trusted verifier must interpret application evidence before authorizing an action.

The enclave reconstructs the native MuSig2 scope before nonce generation.
The scope fixes exact message commitments, item identifiers, signing keys, ordering, subsets, tweaks, and adaptor context.
Full-group items use their item tweak. Subset items use the tweak already committed by keygen.
A caller cannot substitute an alternative native command after obtaining a signing permit.

## Protocol

All phases run inside [confidential transport](CONFIDENTIAL_AUTHORIZATION.md).
The former plaintext `/keygen/{id}/escrow` route is removed.

1. Register the enclave-encrypted key, participant-signed policy, and declared secret deposits.
2. Bind the complete participant policy roster and application data.
3. Prepare an exact permitted action from authenticated binding state and bounded application input.
4. Execute with the preparation receipt and required evidence.
5. For signing, run the native MuSig2 rounds under the resulting exact permit.

Every signed response commits to its request, enclave identity and epoch, output, and enclave-sealed state.
Binding responses commit to the application binding data and exact participant policy digests.
Preparation receipts allow separate permissions to share one authenticated application preparation when explicitly verified.
The engine independently checks each permission and release recipient.

Exact retries preserve request identities and ciphertexts.
Identical-scope signing repetition requires explicit participant consent and fresh signing sessions.
Release permissions are single-use within the live ledger, with exact recovery retries.
The signed `PreparationPolicy` separately controls replacement preparations.
`Single` is the default. `RenewableIdenticalAction` permits bounded replacement candidates for the same fixed-recipient release.
Each replacement authenticates its predecessor and preserves the exact action and binding.
An earlier valid candidate can still execute before another candidate wins.
The first successful execution freezes the permission; replacement preparation does not authorize another release.
This state does not establish global consumption across hostile rollback.
No receipt permits secret nonce reuse or arbitrary replacement messages.

## Pools that never fill

An `unbound` grant needs no application binding. Its verifier authorizes each action from the participant's registered policy alone.
It is allowed only for verifier-authorized `SignBip340`, such as refunding an escrow whose pool never formed.

`ConfidentialSession::register_partial_roster` registers only the participants who are present, including the coordinator.
It never distributes peer keys or requests an aggregate, so no key is ever built from the subset.
Each enclave that holds a present participant keeps the session registering.
A registering session serves unbound prepare and execute for its registered participants, and refuses every other escrow and signing command.
Registrations remain bound to their manifest slot, session, and enclave, so a subset cannot add a participant or reuse another session's registration.
A registration batch the enclave refuses changes nothing, and the session keeps the registrations it holds.
Calling it again replays the exact journaled requests: an enclave that still holds the session answers them without effect, and one that restarted applies them again.
Save the journal of the first call durably, since the enclaves bind the session to its route. A registered roster cannot change.

## Trusted verifiers

`EscrowVerifier` separates enrollment, binding, preparation, and execution checks.
Verifiers receive authenticated context and bounded application bytes.
They never receive custody private keys or deposited secret bytes.
They propose actions; the generic engine enforces the participant's permission.

Preparation and execution checks can await enclave-authenticated external evidence without holding shared custody state locks.
Execution authorization must complete before the engine exposes an authorized effect.
Applications that require an external durable state anchor must include it in that decision.
The engine does not provide an Ark conflicting-spend ledger or a rollback-proof database.

Verifier code belongs to the measured enclave build. Runtime-uploaded code is not supported.
Applications pin the corresponding measurements and recipient key epoch.
The gateway can report generic build support, but application availability comes from the encrypted verifier description query.
A deployment description is not participant consent or permission to sign.

## Build and application boundary

Build generic services with `--features escrow` when generic execution is required.
Default builds keep generic escrow disabled.
The SDK's optional `dlctix` utilities remain client conveniences and do not install enclave rules.

Coordinator owns its DLC verifier, invoice validation, optional LNURL HTTPS, and separate host relay.
Those capabilities are absent from Keymeld's feature set and gateway handlers.
See the [Coordinator deployment documentation](https://github.com/5day4cast/coordinator/blob/main/docs/COORDINATOR_ENCLAVE.md) for that application's build boundary.

The current custody context is a managed session participant.
Persistent imported-key policies and external-party MuSig2 require additional primitives.
