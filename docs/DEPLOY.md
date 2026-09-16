# Deploy KeyMeld 0.4.0 on AWS Nitro

Build measured images, review their manifests and KMS policy, then deploy the reviewed local artifacts.
The helpers do not publish images, download mutable aliases, or change KMS policies.

## Prepare and build

Use a Nitro-capable EC2 instance with [Nitro CLI](https://docs.aws.amazon.com/enclaves/latest/user/nitro-cli-install.html), Nix, and Docker.
Follow [security configuration](SECURITY_OPERATIONS.md#provision-the-gateway-identity) to provision the gateway credential and measured enclave settings.
Follow the [KMS policy procedure](KMS.md#prepare-a-locked-policy) before generating custody state.

Build one image per enclave ID:

```bash
just build-eif
```

Each EIF has a manifest containing its checksum, source commit, version, dirty-source flag, and PCR0/1/2/8.
Use a clean reviewed commit for release artifacts; reject `source_dirty: true`.
Review and combine manifests as described in [measured image deployment](SECURITY_OPERATIONS.md#build-and-deploy-measured-images).

## Start and verify

Start the [parent KMS and credential relays](KMS.md#nitro-network-and-credentials) under a supervised service.
Configure trusted measurements, gateway credentials, and matching KMS settings before deployment.

```bash
export EIF_MANIFEST="$PWD/reviewed-enclaves.json"
export KEYMELD_AWS_ENV_FILE="$PWD/keymeld-aws.env"
just deploy-aws
source "$KEYMELD_AWS_ENV_FILE"
just gateway-aws
```

The deployment helper validates all artifacts before launch and refuses an existing output environment file.
Match gateway enclave IDs and ports to the reviewed configuration.
Check `/api/v1/health` through HTTPS ingress and complete [hardware acceptance](KMS.md#hardware-acceptance).

## Recovery and upgrades

Retain encrypted backups, approved EIFs and manifests, the gateway credential, and the KMS role identity.
Recover with the same approved image, KMS key, and enclave ID.
A PCR0-locked policy fixes the accepted image set; image updates and gateway credential rotation require a planned migration.
Upgrade releases through 0.3.5 to 0.4.0 together with fresh state; do not roll back to affected versions.
See the [0.4.0 upgrade notes](releases/0.4.0.md).
