#!/usr/bin/env bash
# Test generic feature selection and measured identity without Nix, Docker or Nitro builds.
set -euo pipefail
keymeld_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
keymeld_test_dir="$(mktemp -d)"
trap 'rm -rf -- "$keymeld_test_dir"' EXIT
mkdir "$keymeld_test_dir/bin"
export KEYMELD_BUILD_TEST_DIR="$keymeld_test_dir"
export PATH="$keymeld_test_dir/bin:$PATH"
cat > "$keymeld_test_dir/bin/nix" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$KEYMELD_BUILD_TEST_DIR/nix.log"
[[ "$1" == build && "$3" == --out-link && $# == 4 ]]
printf 'mock image archive' > "$4"
MOCK
cat > "$keymeld_test_dir/bin/docker" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  load) cat >/dev/null ;;
  build)
    printf '%s\n' "$@" > "$KEYMELD_BUILD_TEST_DIR/docker.args"
    cp "${!#}/Dockerfile" "$KEYMELD_BUILD_TEST_DIR/Dockerfile"
    ;;
  rmi) ;;
  *) exit 91 ;;
esac
MOCK
cat > "$keymeld_test_dir/bin/nitro-cli" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  build-enclave)
    [[ "$2" == --docker-uri && "$4" == --output-file ]]
    printf 'mock measured enclave' > "$5"
    ;;
  describe-eif) jq -n '{Measurements:{PCR0:("a"*96),PCR1:("b"*96),PCR2:("c"*96)}}' ;;
  *) exit 92 ;;
esac
MOCK
chmod +x "$keymeld_test_dir/bin/"*
export ENCLAVE_GATEWAY_PUBLIC_KEY="02$(printf '1%.0s' {1..64})"
export ENCLAVE_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555
export AWS_REGION=us-east-1 ENCLAVE_ID=7 VERSION=feature-test
unset KEYMELD_ESCROW_VARIANT
unset EIF_SIGNING_KEY EIF_SIGNING_CERTIFICATE EIF_NAME
cd -- "$keymeld_root"

run_case() {
  local feature="$1" suffix="$2"
  export KEYMELD_ESCROW_VARIANT="$feature"
  export OUTPUT_FILE="$keymeld_test_dir/$feature.eif"
  bash scripts/build-enclave-eif.sh > "$keymeld_test_dir/build.log"
  grep -Fq -- "build .#docker-enclave$suffix --out-link " "$keymeld_test_dir/nix.log"
  grep -Fxq -- "BASE_IMAGE=keymeld-enclave$suffix:latest" "$keymeld_test_dir/docker.args"
  grep -Fxq 'ENV TRANSPORT_MODE=vsock' "$keymeld_test_dir/Dockerfile"
  if grep -Eqi 'lnurl|lightning|dlctix' "$keymeld_test_dir/Dockerfile" "$keymeld_test_dir/docker.args"; then
    echo "Generic enclave image contains application-specific configuration" >&2; exit 1
  fi
  jq -e --arg feature "$feature" \
    '.escrow_variant == $feature and .enclave_id == 7 and (has("escrow") | not)' \
    "$OUTPUT_FILE.manifest.json" >/dev/null
  : > "$keymeld_test_dir/nix.log"
}
run_case none ''
jq -e '.cargo_features == []' "$OUTPUT_FILE.manifest.json" >/dev/null
run_case escrow -escrow
jq -e '.cargo_features == ["escrow"]' "$OUTPUT_FILE.manifest.json" >/dev/null

reject_case() {
  export OUTPUT_FILE="$keymeld_test_dir/rejected.eif"
  if bash scripts/build-enclave-eif.sh > "$keymeld_test_dir/rejected.log" 2>&1; then
    echo "Unsupported application build variant was accepted" >&2; exit 1
  fi
  [[ ! -s "$keymeld_test_dir/nix.log" && ! -e "$OUTPUT_FILE" ]]
}
for variant in escrow-lightning escrow-dlctix escrow-lnurl escrow-dlctix-lnurl unrecognized; do
  export KEYMELD_ESCROW_VARIANT="$variant"
  reject_case
done

# Omitted settings produce a feature-free image.
unset KEYMELD_ESCROW_VARIANT
export OUTPUT_FILE="$keymeld_test_dir/default.eif"
bash scripts/build-enclave-eif.sh > "$keymeld_test_dir/default.log"
jq -e '.escrow_variant == "none" and .cargo_features == []' "$OUTPUT_FILE.manifest.json" >/dev/null
printf '%s\n' 'EIF generic escrow build regressions passed (3 builds, 5 rejected configurations; all infrastructure mocked).'
