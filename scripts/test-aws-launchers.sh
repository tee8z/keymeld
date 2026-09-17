#!/usr/bin/env bash
# Exercise deployment configuration with mocked Nitro CLI and gateway binaries.
set -euo pipefail
keymeld_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
keymeld_test_dir="$(mktemp -d)"
trap 'find "$keymeld_test_dir" -depth -delete' EXIT
mkdir "$keymeld_test_dir/bin"
export KEYMELD_LAUNCHER_TEST_DIR="$keymeld_test_dir"
export PATH="$keymeld_test_dir/bin:$PATH"
export ENCLAVE_MEMORY=512 ENCLAVE_CPUS=2
unset KEYMELD_ENCLAVE_0_CID

cat > "$keymeld_test_dir/bin/nitro-cli" <<'NITRO'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$KEYMELD_LAUNCHER_TEST_DIR/nitro.log"
case "$1" in
    describe-eif)
        [[ "$2" == --eif-path && "$3" == "$KEYMELD_LAUNCHER_TEST_DIR/reviewed image.eif" ]]
        jq -n '{Measurements: {PCR0: ("a" * 96), PCR8: ("c" * 96)}}' ;;
    run-enclave)
        [[ "$*" == *'--enclave-name keymeld-enclave-7' && "$*" != *'--debug-mode'* ]]
        jq -n '{EnclaveCID: 27, EnclaveID: "mock-enclave-7"}' ;;
    *) echo "Unexpected Nitro operation" >&2; exit 1 ;;
esac
NITRO
cat > "$keymeld_test_dir/bin/keymeld-gateway" <<'GATEWAY'
#!/usr/bin/env bash
set -euo pipefail
[[ "$KEYMELD_ENVIRONMENT" == production && -f "$CONFIG_PATH" ]]
jq -n '{config: env.CONFIG_PATH, enclave_7: env.KEYMELD_ENCLAVE_7_CID,
    enclave_0: env.KEYMELD_ENCLAVE_0_CID, environment: env.KEYMELD_ENVIRONMENT}' \
    > "$KEYMELD_LAUNCHER_TEST_DIR/gateway.json"
GATEWAY
chmod +x "$keymeld_test_dir/bin/nitro-cli" "$keymeld_test_dir/bin/keymeld-gateway"
printf 'synthetic reviewed EIF bytes' > "$keymeld_test_dir/reviewed image.eif"
keymeld_sha="$(sha256sum "$keymeld_test_dir/reviewed image.eif")"
export EIF_MANIFEST="$keymeld_test_dir/reviewed manifests.json"
jq -n --arg eif "$keymeld_test_dir/reviewed image.eif" --arg sha "${keymeld_sha%% *}" \
    '[{enclave_id: 7, eif_path: $eif, sha256: $sha, pcr0: ("a" * 96)}]' > "$EIF_MANIFEST"
export KEYMELD_ENCLAVE_PCR8
KEYMELD_ENCLAVE_PCR8="$(printf 'c%.0s' {1..96})"
export KEYMELD_AWS_ENV_FILE="$keymeld_test_dir/reviewed deployment.env"
export CONFIG_PATH="$keymeld_test_dir/reviewed production.yaml"
cat > "$CONFIG_PATH" <<'CONFIG'
environment: production
kms:
  enabled: true
  key_id: arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555
enclaves:
  enclaves:
    - { id: 7, cid: 27, port: 8000 }
CONFIG
cp "$CONFIG_PATH" "$keymeld_test_dir/invocation override.yaml"

cd -- "$keymeld_test_dir"
bash "$keymeld_root/scripts/deploy-aws-enclaves.sh" > "$keymeld_test_dir/deployment.log"
[[ "$(grep -c '^run-enclave ' "$keymeld_test_dir/nitro.log")" == 1 ]]
[[ "$(grep -c '^describe-eif ' "$keymeld_test_dir/nitro.log")" == 1 ]]
# A custom environment path must win over a stale default in the same directory.
printf 'echo "Wrong deployment environment loaded" >&2\nexit 91\n' > keymeld-aws.env
unset CONFIG_PATH
bash "$keymeld_root/scripts/start-aws-gateway.sh" "$keymeld_test_dir/bin/keymeld-gateway"
jq -e --arg config "$keymeld_test_dir/reviewed production.yaml" \
    '.config == $config and .enclave_7 == "27" and .enclave_0 == null and .environment == "production"' \
    "$keymeld_test_dir/gateway.json" >/dev/null

# Explicit invocation configuration overrides the recorded deployment default.
export CONFIG_PATH="$keymeld_test_dir/invocation override.yaml"
bash "$keymeld_root/scripts/start-aws-gateway.sh" "$keymeld_test_dir/bin/keymeld-gateway"
jq -e --arg config "$CONFIG_PATH" '.config == $config' "$keymeld_test_dir/gateway.json" >/dev/null

# Existing output files must fail before starting another enclave.
if bash "$keymeld_root/scripts/deploy-aws-enclaves.sh" >/dev/null 2>&1; then
    echo "Deployment overwrote its existing environment file." >&2; exit 1
fi
[[ "$(grep -c '^run-enclave ' "$keymeld_test_dir/nitro.log")" == 1 ]]

export KEYMELD_AWS_ENV_FILE="$keymeld_test_dir/missing.env"
if bash "$keymeld_root/scripts/start-aws-gateway.sh" "$keymeld_test_dir/bin/keymeld-gateway" >/dev/null 2>&1; then
    echo "Launcher ignored a missing explicitly selected environment file." >&2; exit 1
fi

# Direct launch still supports a reviewed config without any deployment file.
mkdir "$keymeld_test_dir/direct"
cd -- "$keymeld_test_dir/direct"
unset KEYMELD_AWS_ENV_FILE
export KEYMELD_ENCLAVE_7_CID=37 KEYMELD_ENVIRONMENT=development
bash "$keymeld_root/scripts/start-aws-gateway.sh" "$keymeld_test_dir/bin/keymeld-gateway"
jq -e --arg config "$CONFIG_PATH" \
    '.config == $config and .enclave_7 == "37" and .environment == "production"' \
    "$keymeld_test_dir/gateway.json" >/dev/null

# A checksum mismatch is rejected before invoking Nitro CLI.
export KEYMELD_AWS_ENV_FILE="$keymeld_test_dir/rejected.env"
printf 'changed' >> "$keymeld_test_dir/reviewed image.eif"
: > "$keymeld_test_dir/nitro.log"
if bash "$keymeld_root/scripts/deploy-aws-enclaves.sh" >/dev/null 2>&1; then
    echo "Deployment accepted an altered EIF." >&2; exit 1
fi
[[ ! -s "$keymeld_test_dir/nitro.log" ]]
echo "AWS launcher mock regressions passed; no Nitro or AWS operations were performed."
