# KMS integration

KeyMeld uses attested AWS KMS calls to recover its enclave key hierarchy after a restart.
Upgrade the gateway, enclave images, and SDK together to 0.4.0 with fresh state.

## Current trust boundary

Production `GenerateDataKey` and `Decrypt` requests include a Nitro `Recipient` attestation document.
The enclave creates a separate, temporary RSA-2048 key and asks NSM to attest its public key with a fresh challenge.
It requires `CiphertextForRecipient`; missing ciphertext or a nonempty `Plaintext` field causes failure.
It opens the AWS CMS envelope inside the enclave and requires RSA-OAEP-SHA256, AES-256-CBC, and a 32-byte DEK.
The temporary recipient key is separate from the secp256k1 custody and channel keys.

The enclave pins a complete KMS key ARN and its regional HTTPS endpoint in the measured image.
Aliases, HTTP endpoints, alternate hosts, ports, and gateway-selected trust roots are rejected in production.
The KMS TLS client uses only the bundled Amazon Trust Services roots.
Before custody operations, `DescribeKey` must confirm an enabled, AWS-generated, single-Region symmetric key with the pinned ARN.
It overrides ambient service endpoints and does not use ambient TLS roots for KMS.
TLS ends inside the enclave; the parent forwards encrypted bytes.

These client protections must be combined with an attestation-only KMS key policy.
Without that policy, another principal with ordinary `kms:Decrypt` permission can recover a stored DEK outside the enclave.
AWS describes the response contract in [attested KMS calls](https://docs.aws.amazon.com/kms/latest/developerguide/attested-calls.html).
The [locked policy procedure](#prepare-a-locked-policy) removes ordinary decryption and policy administration from the account operator.

This design still trusts AWS Nitro, NSM, KMS, the approved image, and its cryptographic dependencies.
The operator can interrupt service, withhold state, or roll back external storage.
Attestation and KMS do not prove an application's intended transaction or prevent rollback of external state.
Participant approvals and durable application policy remain necessary.

## Key lifecycle

1. Generate the enclave's secp256k1 keypair inside the enclave.
2. Request an attested KMS DEK and open its recipient envelope inside the enclave.
3. Encrypt the private key with that DEK using AES-256-GCM.
4. Return only the encrypted DEK, encrypted private key, and public identity to the gateway.
5. On restart, request attested decryption under the pinned KMS key ARN.
6. Recover the private key and verify the public identity through the authenticated channel.

The encryption context contains only `enclave_id`.
Configured PCR strings are no longer copied into encryption context as if they were attestation evidence.
AWS evaluates the signed NSM measurements through `kms:RecipientAttestation` conditions instead.
Old hierarchies using additional PCR context labels require their original context and are outside this fresh-state upgrade.

## Configuration

Production gateway configuration:

```yaml
kms:
  enabled: true
  endpoint_url: null
  key_id: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789abc"
```

Replace the example ARN with the deployment's dedicated symmetric KMS key ARN.
Bake that ARN as `ENCLAVE_KMS_KEY_ID` in the enclave image.
Set `ENCLAVE_KMS_ENDPOINT=aws-kms` and the matching `AWS_REGION`.
An exact regional HTTPS endpoint is also accepted when both gateway and enclave configurations match.
The authenticated channel rejects any configuration that differs from these measured settings.

`security.enable_attestation` must agree with the gateway's actual channel verification mode.
Production requires attestation; configuration cannot silently select the development bypass.
See [security configuration](SECURITY_OPERATIONS.md) for gateway credentials and SDK measurement pins.

## Nitro network and credentials

Nitro enclaves have no external network interface.
AWS's [KMS connection guide](https://docs.aws.amazon.com/enclaves/latest/user/connect-enclave-kms.html) describes the parent VSock relay and temporary credential requirement.

The measured image's `scripts/nitro-entrypoint.sh` prepares two loopback relays:

| Enclave listener | Parent destination | Purpose |
| --- | --- | --- |
| `127.0.0.1:443` | CID 3, port 8000 | End-to-end TLS to the pinned regional KMS host |
| `127.0.0.1:8001` | CID 3, port 8001 | IMDSv2 credential refresh using the parent instance role |

The entrypoint maps only the pinned KMS hostname to loopback.
The SDK still verifies that hostname and the AWS TLS chain.
The IMDS endpoint supplies temporary role credentials, which the parent already controls.
Those credentials alone cannot decrypt under the locked policy.
Do not bake credentials, participant keys, or session secrets into an EIF.

Before starting enclaves, run `scripts/nitro-parent-proxies.sh` under a dedicated service on the parent.
Use the same pinned `ENCLAVE_KMS_KEY_ID` and `AWS_REGION` as the images.
The helper forwards only to regional KMS port 443 and IMDS at `169.254.169.254:80`.
Do not expose these listeners through a public TCP forwarding service.
The enclave entrypoint terminates the enclave if either required relay exits.

## Prepare a locked policy

The supplied template pins the approved PCR0 values and one instance role.
It allows only attested `GenerateDataKey` and `Decrypt`, plus policy, grant, and key inspection.
Explicit denies cover other principals, missing or different measurements, policy changes, grants, and other cryptographic operations.
The template has no account-root delegation or policy administrator.
AWS documents [key policy authorization](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html) and [attestation conditions](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html).

Render a review artifact from trusted EIF manifests:

```bash
bash scripts/render-locked-kms-policy.sh \
  arn:aws:iam::123456789012:role/keymeld-enclave \
  reviewed-enclaves.json > reviewed-kms-policy.json
```

The renderer rejects root principals, wildcards, empty image lists, duplicate enclave IDs, and zero debug measurements.
It makes no AWS calls and does not install the policy.
Inspect the generated JSON, role ARN, key ARN, and image measurements together.

**Applying this policy removes policy administration and fixes the accepted images.**
Future image upgrades require a new key and an explicit migration design.
Keep the approved EIF artifacts and role identity available for recovery.
Back up the gateway command credential securely; its public verifier is also fixed inside those images.
Losing that credential cannot be repaired by changing the image under a PCR0-locked policy.
Replacing the role can also remove access; the policy cannot then be repaired through normal administration.
AWS's [PutKeyPolicy safety check](https://docs.aws.amazon.com/kms/latest/APIReference/API_PutKeyPolicy.html) exists to prevent this lockout.
Do not bypass that check until the concrete deployment and recovery procedure have been reviewed.

Use a dedicated, enabled, single-Region symmetric key with AWS-generated key material.
Inspect and remove existing grants before final lock-down.
Complete the hardware acceptance procedure below on disposable resources first.
Generate the deployment's custody hierarchy only after the final policy is installed.
Locking a policy cannot revoke plaintext DEKs or keys copied before lock-down.
Apply the final policy only after review; this repository's build and deployment helpers do not apply it.
Retaining a `PutKeyPolicy` administrator retains that administrator's ability to change the custody boundary.

## Hardware acceptance

These checks require a Nitro-capable EC2 instance and dedicated test KMS resources.
Local fixtures do not establish successful AWS deployment.
For an existing test deployment, run [`scripts/test-nitro-kms-e2e.sh --help`](../scripts/test-nitro-kms-e2e.sh)
for the policy, denial, and SDK checks. Complete the remaining hardware checks below separately.

1. Record the commit, EIF checksum, PCR0/1/2/8, key ARN, role ARN, and exact policy.
2. Verify the KMS key configuration and confirm that no grants exist.
3. Start the approved image without debug mode and verify SDK and gateway attestation.
4. Create synthetic keys, sign a reviewed batch, and record the verified aggregate key.
5. Restart the gateway and enclaves with retained ciphertext; verify the same key and another valid signature.
6. From the parent role, call `GenerateDataKey` without `Recipient`; require `AccessDeniedException`.
7. Attempt ordinary `Decrypt` of the saved encrypted DEK; require `AccessDeniedException`.
8. Repeat the KMS calls from a debug enclave and an unapproved image; require denial.
9. Redirect the parent KMS relay to a foreign TLS service; require TLS failure and no initialized hierarchy.
10. Verify the locked policy denies administration and alternate cryptographic operations; do not test by changing a live policy.
11. Retain the successful and rejected requests' CloudTrail events with the acceptance artifacts.

AWS records attestation measurements in `additionalEventData.recipient` for [Nitro KMS events](https://docs.aws.amazon.com/kms/latest/developerguide/ct-nitro-enclave.html).
Compare `attestationDocumentEnclaveImageDigest` with the reviewed PCR0, and retain module IDs and request IDs.
Monitor changes to key policy, grants, role policy, and the approved image set before lock-down.
Publish reviewed measurement and policy artifacts separately from private credentials.
A second clean image build must reproduce the measured configuration before making reproducibility claims.

## Local verification

```bash
cargo test -p keymeld-enclave --locked
bash scripts/test-locked-kms-policy.sh
nix develop -c bash examples/run-authorization-e2e.sh
```

Rust fixtures exercise attested request fields, CMS decryption, algorithm rejection, malformed replies, and plaintext downgrade rejection.
A real TLS fixture verifies rejection of a foreign KMS certificate before HTTP.
The isolated live suite uses Moto and explicit development configuration for signing and restart tests.
Only that configuration permits plaintext KMS responses; production has no fallback after NSM, TLS, or recipient failure.
Moto does not verify Nitro attestation or the locked AWS policy.

## Troubleshooting

| Symptom | Corrective action |
| --- | --- |
| `AccessDeniedException` | Compare role, key ARN, fresh NSM document, and approved image measurements with the policy. |
| TLS failure | Check the fixed KMS destination, relay, clock, and approved AWS root bundle. Do not disable verification. |
| No AWS credentials | Check both IMDS relay endpoints and the parent instance role's IMDSv2 access. |
| `IncorrectKeyException` | Restore the key ARN that matches the archived hierarchy. |
| Encryption context mismatch | Restore the original enclave ID; use fresh state for this upgrade. |
| Configuration rejected | Match gateway settings to the measured image's key ARN, endpoint, ID, and verifier. |
| Recipient missing or plaintext returned | Confirm strict production mode and real AWS KMS; do not substitute a plaintext fallback. |
