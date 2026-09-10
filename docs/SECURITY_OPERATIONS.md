# Security configuration for the 0.4 protocol

Upgrade the gateway, enclaves, and SDK together with fresh session state.
The [authorization guide](AUTHORIZATION.md) describes participant credentials and migration.

## Provision the gateway identity

Create a gateway command credential in a private directory:

```bash
install -d -m 700 ./keys
keymeld-gateway --generate-channel-key ./keys/gateway-channel.key
export KEYMELD_GATEWAY_SIGNING_KEY_FILE="$PWD/keys/gateway-channel.key"
export ENCLAVE_GATEWAY_PUBLIC_KEY="$(keymeld-gateway --channel-public-key "$KEYMELD_GATEWAY_SIGNING_KEY_FILE")"
```

The credential-generation command prints only the public key.
The credential file contains the private key and has mode `0600` on Unix.
Generation refuses to replace an existing file.
Keep this credential independent of participant, signing, and session credentials.

Provision the public key inside the measured enclave image before starting the enclave.
The enclave must not learn its trusted gateway key from its first network caller.
Also provision `ENCLAVE_KMS_KEY_ID` and `ENCLAVE_KMS_ENDPOINT` inside that image.
Use `aws-kms` for the default AWS endpoint, or the intended proxy URL for a configured KMS proxy.
Set `AWS_REGION` in the image for the default AWS endpoint.

Every command requires the pinned gateway signature, a fresh timestamp, and the current enclave boot identifier.
The enclave caches an identical command's outcome and rejects changed content under the same command identifier.
Commands captured before an enclave restart cannot execute after that restart.

Configuration must match the provisioned enclave ID, KMS endpoint, and KMS key.
An initialized enclave rejects another configuration command.
A gateway restart inspects the authenticated live enclave before deciding whether configuration is needed.

## Verify the enclave before sending secrets

The gateway requires `KEYMELD_ENCLAVE_PCR0` or `KEYMELD_ENCLAVE_PCR8`.
Each value is a nonzero, hexadecimal SHA-384 measurement from a trusted image build or signing certificate.
PCR0 pins an image; PCR8 pins its image signer.
If both values are configured, both must match.
Do not obtain trusted measurements from the gateway being verified.
For this upgrade, replace old PCR0 pins with reviewed `0.4.0` image measurements.
If using PCR8, provision a new image signing certificate for `0.4.0` and remove the old signer pin.
A signer pin alone also accepts older images signed by that certificate.

The enclave creates a fresh channel signing key at each boot.
Before configuration, the gateway requests attestation for that key with a fresh random challenge.
The verifier checks the original COSE signature, certificate chain, pinned AWS root, certificate dates, measurements, challenge, and public key.
It also rejects expired documents and debug enclave measurements.
Every command response is signed by the verified channel key and bound to the originating command.

Configure SDK clients with the same trusted measurement policy:

```rust
use keymeld_sdk::{AttestationPolicy, KeyMeldClient, UserId};
use std::collections::BTreeMap;

let policy = AttestationPolicy::new(BTreeMap::from([(0, trusted_pcr0_bytes)]))?;
let client = KeyMeldClient::builder(gateway_url, UserId::new_v7())
    .attestation_policy(policy)
    .credentials(user_credentials)
    .build()?;
```

The SDK verifies fresh attestation before encrypting private keys or session secrets to an enclave.
Default clients reject key custody operations until a policy is supplied.
The creator also authorizes the verified enclave recipient roster before enclave-to-enclave session-secret distribution.

Attestation authenticates the measured code and recipient key.
It does not validate an application's intended participants, transaction, or funding decision.
Keep the participant, roster, and signing checks from the authorization guide.

## Build and deploy measured images

Build a separate enclave image for each configured enclave ID.
The gateway verifier, pinned KMS endpoint and key identifier, and enclave ID are measured image configuration.
The build helper includes the Nix runtime closure and refuses to replace existing artifacts.

Set `ENCLAVE_ID`, `ENCLAVE_GATEWAY_PUBLIC_KEY`, `ENCLAVE_KMS_KEY_ID`, `ENCLAVE_KMS_ENDPOINT`, and `AWS_REGION` before building.
For a cluster, sign each image with the same approved image signer and pin its PCR8 measurement.
Set `EIF_SIGNING_KEY` to the signing key path or KMS ARN and `EIF_SIGNING_CERTIFICATE` to the matching certificate path.

```bash
nix run .#build-eif
```

Each build writes an EIF and a sibling `.manifest.json` file.
The manifest records its enclave ID, file path, SHA-256 checksum, PCR0, and PCR8.
Review these outputs against the intended configuration before deployment.

Combine the reviewed per-enclave manifests into an array:

```bash
jq -s '.' enclave-0.eif.manifest.json enclave-1.eif.manifest.json enclave-2.eif.manifest.json > reviewed-enclaves.json
export EIF_MANIFEST="$PWD/reviewed-enclaves.json"
export KEYMELD_ENCLAVE_PCR8=TRUSTED_SIGNER_PCR8
export KEYMELD_AWS_ENV_FILE="$PWD/keymeld-aws.env"
nix run .#deploy-aws
```

Replace the example filenames with the actual reviewed artifacts.
The deployment helper verifies all identifiers, checksums, and measurements before launching an enclave.
It uses no debug mode and refuses to overwrite an existing environment file.
Its output records the assigned enclave CIDs; source that file when starting the gateway.
Configure the gateway's enclave IDs to match the reviewed manifest.
The build helper does not upload artifacts or update published aliases.


## Local simulation

Run the isolated security regressions with synthetic keys:

```bash
nix develop -c bash examples/run-authorization-e2e.sh
```

The runner creates a temporary gateway credential and pins its public key in all three simulated enclaves.
It also pins the temporary Moto KMS endpoint and key.
Only this explicit development setup disables attestation verification.
Command authentication and participant authorization remain required.

The local launchers use `scripts/development-auth.sh` to provision an ignored development credential.
The helper explicitly selects `KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES=true` for simulation.
SDK callers can explicitly select `.dangerous_trust_unattested_enclaves()` for their synthetic test clients.
Production gateway configuration rejects the simulation environment flag.
TCP enclave listeners bind to `127.0.0.1` by default.

## Protect operator pages

Operator pages and their HTML fragments are disabled by default.
To enable them, configure `KEYMELD_OPERATOR_TOKEN_FILE` with a private file containing a random operator token.
Requests must include `Authorization: Bearer <operator-token>`.
Use an authenticated reverse proxy for browser access, or set the header in an operator HTTP client.
The operator token is separate from all participant and gateway command credentials.

For simulated Helm deployments, provision a Kubernetes Secret containing `gateway-signing-key`.
Set `channel.existingSecret` to that Secret and `channel.gatewayPublicKey` to its public key.
Explicitly select development configuration and `channel.dangerousTrustUnattestedEnclaves: true` for simulation.
The chart mounts the private credential only in gateway containers.
Enclave containers receive the public verifier and KMS policy.

## Acceptance before release

Run workspace tests, Clippy, WASM compilation, SQLx checks, and the isolated security regressions on the reviewed commit.
The live suite must retain valid signing after rejected attacks, gateway restart, and full enclave restart.
Run the release workflow as a dry run before tagging.

Real Nitro deployment requires an additional hardware acceptance run with the final measured image and KMS policy.
Verify signed attestation, rejected debug mode, gateway credential rejection, KMS recovery, and signing after restart on that deployment.
Local TCP tests and signed attestation fixtures cannot establish hardware deployment readiness.
KMS recovery currently trusts IAM-authorized callers and does not use Nitro `Recipient` attestation.
See the [KMS trust boundary](KMS.md#current-trust-boundary) before choosing a custody deployment.
See the [release process](../.github/RELEASE.md) for publication and affected-version notices.
