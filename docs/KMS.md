# KMS integration

KeyMeld uses AWS KMS to recover its enclave key hierarchy after a restart.
The gateway stores an encrypted data encryption key (DEK), encrypted enclave private key, public key, and KMS key identifier.

## Current trust boundary

The enclave calls `GenerateDataKey` and `Decrypt` through the standard AWS SDK and consumes their `Plaintext` responses.
These calls use IAM authorization and do not supply Nitro `Recipient` attestation.
A principal with `kms:Decrypt` permission and the stored ciphertext and encryption context can recover the DEK outside the enclave.
Treat that KMS principal and any TLS-terminating KMS proxy as trusted custody components.

The 0.4.0 client and gateway attestation checks authenticate enclave keys before sending secrets or commands.
They do not change the KMS recovery trust boundary.
The KMS encryption context includes the enclave ID and any configured PCR labels; these labels are caller-supplied metadata, not attestation evidence.

Enclave-only KMS recovery requires additional implementation: supply `Recipient`, decrypt `CiphertextForRecipient` inside the enclave, and enforce an attestation-based KMS policy.
AWS documents this protocol in [attested KMS calls](https://docs.aws.amazon.com/kms/latest/developerguide/attested-calls.html).
A policy that requires `kms:RecipientAttestation` rejects the current implementation's calls.
Hardware testing alone does not add this missing protocol.

## Key lifecycle

1. The enclave generates its secp256k1 keypair.
2. KMS generates a DEK and returns plaintext and encrypted copies.
3. The enclave encrypts its private key with the DEK using AES-256-GCM.
4. The gateway stores both encrypted values and their KMS key identifier.
5. On restart, the enclave asks KMS to decrypt the DEK under the pinned KMS key.
6. The enclave decrypts its private key and verifies the recovered public identity through the authenticated channel.

The DEK remains in enclave memory while keys are in use.
The gateway command response contains the encrypted hierarchy, not the plaintext DEK.
An authorized caller's ability to obtain plaintext from KMS is described above.

## Configuration

For local simulation with Moto:

```yaml
kms:
  enabled: true
  endpoint_url: "http://127.0.0.1:4566"
  key_id: "alias/keymeld-enclave-master-key"
```

For the standard regional AWS endpoint:

```yaml
kms:
  enabled: true
  endpoint_url: null
  key_id: "arn:aws:kms:us-west-2:ACCOUNT:key/KEY_ID"
```

Provision matching `ENCLAVE_KMS_ENDPOINT` and `ENCLAVE_KMS_KEY_ID` values in the enclave image.
Use `aws-kms` for `ENCLAVE_KMS_ENDPOINT` when the gateway endpoint is `null`.
Set `AWS_REGION` to the intended region.
Use a key ARN to pin a specific key; aliases can be reassigned outside KeyMeld.
There is no `kms.enable_attestation` configuration field.

The enclave rejects configuration with a different endpoint or key identifier.
An initialized enclave rejects another configuration command.
Restoration passes the pinned key identifier to `Decrypt`; ciphertext for a different key must fail.
See the [AWS Decrypt reference](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) for the `KeyId` behavior.

See [security configuration](SECURITY_OPERATIONS.md) for gateway credentials, measured image configuration, SDK attestation policy, and deployment acceptance.

## Permissions and deployment

Grant `kms:GenerateDataKey` and `kms:Decrypt` only for the intended KMS key.
Provision credentials for the enclave's KMS client according to the deployment's credential delivery mechanism.
If a parent-instance process can use the same permissions, that process is also trusted for recovery of the stored hierarchy.
A proxy that forwards end-to-end TLS bytes does not necessarily receive plaintext; a proxy that terminates TLS does.

The enclave image contains the pinned endpoint and key identifier.
AWS IAM and KMS key policies remain external configuration and are not measured image contents.
Record those policies with the reviewed deployment configuration.

## Testing

```bash
nix develop -c bash examples/run-authorization-e2e.sh
```

The isolated runner uses temporary Moto keys and a fresh database.
It verifies authorized signing, key persistence, gateway-only restart, and full enclave restart.
The workspace's Rust KMS fixture verifies that encrypted hierarchy restoration rejects a different key, using AWS's documented behavior.
Moto 5.1.11 ignores `KeyId` during decrypt, so it cannot validate that negative case.
The simulation does not verify real Nitro networking, IAM credential delivery, or attested KMS recovery.

## Troubleshooting

| Symptom | Check and corrective action |
| --- | --- |
| `AccessDeniedException` | Check the client's IAM principal and the intended KMS key policy. An attestation-only policy cannot authorize the current un-attested calls. |
| `IncorrectKeyException` | Check the configured key ARN and the archived hierarchy's key identifier. Restore the matching configuration and archive. |
| Encryption context mismatch | Restore the original enclave ID and context configuration. |
| Configuration rejected | Match the gateway's endpoint and key identifier to the values provisioned in the enclave image. |
| Gateway cannot restore after restart | Confirm the persisted encrypted hierarchy, KMS access, enclave assignments, and matching 0.4.0 protocol state. |
