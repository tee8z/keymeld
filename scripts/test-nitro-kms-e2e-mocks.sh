#!/usr/bin/env bash
# Regression tests for the manual acceptance helper. AWS and cargo are mocked;
# this script never contacts AWS, starts services, or changes host networking.
set -euo pipefail
keymeld_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
keymeld_test_dir="$(mktemp -d)"
trap 'rm -rf -- "$keymeld_test_dir"' EXIT
mkdir "$keymeld_test_dir/bin"
export KEYMELD_KMS_KEY_ARN=arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555
export KEYMELD_KMS_ROLE_ARN=arn:aws:iam::123456789012:role/service/keymeld-enclave
export KEYMELD_EIF_MANIFEST="$keymeld_test_dir/image.json"
export KEYMELD_TEST_GATEWAY_URL=https://gateway.example.test
export KEYMELD_ENCLAVE_PCR0
KEYMELD_ENCLAVE_PCR0="$(printf 'a%.0s' {1..96})"
export KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES=false
unset KEYMELD_ENCLAVE_PCR8 KEYMELD_ENCRYPTED_DEK_FILE AWS_ENDPOINT_URL AWS_ENDPOINT_URL_KMS AWS_ENDPOINT_URL_STS AWS_REGION AWS_DEFAULT_REGION
export KEYMELD_MOCK_DIR="$keymeld_test_dir" KEYMELD_MOCK_MODE=pass
jq -n --arg pcr "$KEYMELD_ENCLAVE_PCR0" --arg arn "$KEYMELD_KMS_KEY_ARN" \
    '{enclave_id: 0, pcr0: $pcr, pcr8: ("c" * 96), kms_key_arn: $arn, aws_region: "us-east-1", kms_endpoint: "aws-kms"}' > "$KEYMELD_EIF_MANIFEST"
jq '[.]' "$KEYMELD_EIF_MANIFEST" > "$keymeld_test_dir/images.json"
bash "$keymeld_root/scripts/render-locked-kms-policy.sh" "$KEYMELD_KMS_ROLE_ARN" "$keymeld_test_dir/images.json" > "$keymeld_test_dir/policy.json"
printf 'synthetic encrypted DEK fixture' > "$keymeld_test_dir/dek.bin"

cat > "$keymeld_test_dir/bin/aws" <<'MOCK_AWS'
#!/usr/bin/env bash
set -euo pipefail
[[ -z "${LD_LIBRARY_PATH:-}" ]] || exit 98
service="$1" operation="$2"
shift 2
printf '%s\n' "$service $operation $*" >> "$KEYMELD_MOCK_DIR/aws.log"
region='' endpoint='' query='' key_id=''
while (( $# > 0 )); do
    case "$1" in
        --region) region="$2"; shift 2 ;;
        --endpoint-url) endpoint="$2"; shift 2 ;;
        --query) query="$2"; shift 2 ;;
        --key-id) key_id="$2"; shift 2 ;;
        --recipient|--no-verify-ssl|--no-paginate|--debug) exit 97 ;;
        *) shift ;;
    esac
done
[[ "$region" == us-east-1 && "$endpoint" == "https://$service.us-east-1.amazonaws.com" ]] || exit 96
if [[ "$service" == kms ]]; then [[ "$key_id" == "$KEYMELD_KMS_KEY_ARN" ]] || exit 95; fi
case "$service/$operation" in
    sts/get-caller-identity)
        role=keymeld-enclave
        [[ "$KEYMELD_MOCK_MODE" != wrong-role ]] || role=attacker
        jq -n --arg role "$role" '{Account: "123456789012", Arn: ("arn:aws:sts::123456789012:assumed-role/" + $role + "/session")}' ;;
    kms/describe-key)
        jq -n --arg arn "$KEYMELD_KMS_KEY_ARN" --arg mode "$KEYMELD_MOCK_MODE" '{KeyMetadata: {
            Arn: (if $mode == "wrong-key" then "arn:aws:kms:us-east-1:123456789012:key/other" else $arn end),
            Enabled: ($mode != "disabled"), KeyState: "Enabled", KeyManager: "CUSTOMER",
            KeySpec: (if $mode == "asymmetric" then "RSA_2048" else "SYMMETRIC_DEFAULT" end),
            KeyUsage: "ENCRYPT_DECRYPT", Origin: (if $mode == "external" then "EXTERNAL" else "AWS_KMS" end),
            MultiRegion: ($mode == "multi-region")}}' ;;
    kms/get-key-policy)
        jq -n --slurpfile policy "$KEYMELD_MOCK_DIR/policy.json" --arg mode "$KEYMELD_MOCK_MODE" \
            '{Policy: ($policy[0] | if $mode == "policy-admin" then .Statement += [{Effect: "Allow", Action: "kms:PutKeyPolicy", Resource: "*", Principal: "*"}] else . end | tojson)}' ;;
    kms/list-grants)
        jq -n --arg mode "$KEYMELD_MOCK_MODE" '{Grants: (if $mode == "grants" then [{GrantId: "bad-grant"}] else [] end), Truncated: ($mode == "truncated")}' ;;
    kms/generate-data-key|kms/decrypt)
        [[ "$query" == KeyId ]] || exit 94
        case "$KEYMELD_MOCK_MODE/$operation" in
            plaintext-success/generate-data-key|decrypt-success/decrypt)
                echo "THIS-MUST-NEVER-REACH-TEST-OUTPUT"; exit 0 ;;
            transport-error/*)
                echo 'Could not connect to endpoint URL' >&2; exit 255 ;;
            provider-denied/*)
                echo 'An error occurred (AccessDenied) when calling the AssumeRole operation: denied' >&2; exit 254 ;;
        esac
        api_operation=GenerateDataKey
        [[ "$operation" != decrypt ]] || api_operation=Decrypt
        echo "An error occurred (AccessDeniedException) when calling the $api_operation operation: denied" >&2
        exit 254 ;;
    *) echo "Unexpected AWS operation: $service/$operation" >&2; exit 93 ;;
esac
MOCK_AWS
cat > "$keymeld_test_dir/bin/cargo" <<'MOCK_CARGO'
#!/usr/bin/env bash
set -euo pipefail
[[ "$KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES" == false && "$KEYMELD_TEST_GATEWAY_URL" == https://gateway.example.test ]] || exit 92
[[ -n "${KEYMELD_ENCLAVE_PCR0:-}${KEYMELD_ENCLAVE_PCR8:-}" && "$CARGO_INCREMENTAL" == 0 && -z "$RUSTC_WRAPPER" ]] || exit 91
printf '%s\n' "$*" >> "$KEYMELD_MOCK_DIR/cargo.log"
[[ "$KEYMELD_MOCK_MODE" != cargo-failure ]] || exit 90
if [[ " $* " == *' --list '* ]]; then
    name=''
    while (( $# > 0 )); do
        case "$1" in --exact) name="$2"; shift 2 ;; *) shift ;; esac
    done
    case "$KEYMELD_MOCK_MODE" in
        zero-tests) echo '0 tests, 0 benchmarks' ;;
        renamed-test) echo 'different_test: test'; echo '1 test, 0 benchmarks' ;;
        *) echo "$name: test"; echo '1 test, 0 benchmarks' ;;
    esac
fi
MOCK_CARGO
chmod +x "$keymeld_test_dir/bin/aws" "$keymeld_test_dir/bin/cargo"
export PATH="$keymeld_test_dir/bin:$PATH"

run_helper() {
    : > "$keymeld_test_dir/aws.log"
    : > "$keymeld_test_dir/cargo.log"
    bash "$keymeld_root/scripts/test-nitro-kms-e2e.sh" > "$keymeld_test_dir/output" 2>&1
}
expect_failure() {
    if run_helper; then echo "Accepted unsafe scenario: $*" >&2; exit 1; fi
    [[ ! -s "$keymeld_test_dir/cargo.log" ]] || {
        echo "Rust tests started before failed preflight: $*" >&2; exit 1;
    }
    if grep -q THIS-MUST-NEVER "$keymeld_test_dir/output"; then
        echo "Unexpected successful KMS output was exposed." >&2; exit 1
    fi
}

run_helper
LD_LIBRARY_PATH=/nonexistent/keymeld-test-library-path run_helper
[[ "$(wc -l < "$keymeld_test_dir/cargo.log")" == 4 ]]
grep -q -- '--test approval_binding -- --ignored --exact required_approvals_bind_the_reviewed_complete_batch' "$keymeld_test_dir/cargo.log"
grep -q -- '--test key_lifecycle -- --ignored --exact key_lifecycle_authentication_and_ciphertext_transplant_attacks' "$keymeld_test_dir/cargo.log"
grep -q 'Hardware matrix remains incomplete' "$keymeld_test_dir/output"
grep -q 'generate-data-key.*--key-spec AES_256.*--query KeyId' "$keymeld_test_dir/aws.log"

export KEYMELD_ENCRYPTED_DEK_FILE="$keymeld_test_dir/dek.bin"
run_helper
grep -q -- 'decrypt.*--encryption-context enclave_id=0.*--ciphertext-blob fileb://.*--query KeyId' "$keymeld_test_dir/aws.log"
export KEYMELD_MOCK_MODE=decrypt-success
expect_failure decrypt-success
unset KEYMELD_ENCRYPTED_DEK_FILE
for KEYMELD_MOCK_MODE in wrong-role wrong-key disabled asymmetric external multi-region policy-admin grants truncated plaintext-success transport-error provider-denied; do
    export KEYMELD_MOCK_MODE
    expect_failure "$KEYMELD_MOCK_MODE"
done
export KEYMELD_MOCK_MODE=pass

export KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES=true
expect_failure simulation
export KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES=false
export KEYMELD_TEST_GATEWAY_URL=http://gateway.example.test
expect_failure insecure-gateway
export KEYMELD_TEST_GATEWAY_URL=https://gateway.example.test
export AWS_ENDPOINT_URL=http://localhost:4566
expect_failure emulator-endpoint
unset AWS_ENDPOINT_URL
export AWS_REGION=us-west-2
expect_failure wrong-region
unset AWS_REGION
export KEYMELD_ENCLAVE_PCR0=''
expect_failure missing-measurements
KEYMELD_ENCLAVE_PCR0="$(printf '0%.0s' {1..96})"
expect_failure debug-measurements
KEYMELD_ENCLAVE_PCR0="$(printf 'b%.0s' {1..96})"
expect_failure wrong-measurement
KEYMELD_ENCLAVE_PCR0="$(printf 'a%.0s' {1..96})"
cp "$KEYMELD_EIF_MANIFEST" "$keymeld_test_dir/valid-image.json"
for keymeld_bad in 'del(.kms_key_arn)' '.kms_key_arn = "other-key"' '.aws_region = "us-west-2"' '.kms_endpoint = "https://localhost:4566"'; do
    jq "$keymeld_bad" "$keymeld_test_dir/valid-image.json" > "$KEYMELD_EIF_MANIFEST"
    expect_failure wrong-manifest-target
    [[ ! -s "$keymeld_test_dir/aws.log" ]]
done

# Distinct image PCR0 values use their common, trusted signing measurement.
export KEYMELD_ENCLAVE_PCR0=''
export KEYMELD_ENCLAVE_PCR8
KEYMELD_ENCLAVE_PCR8="$(printf 'c%.0s' {1..96})"
jq -n --arg arn "$KEYMELD_KMS_KEY_ARN" '
    [{enclave_id: 0, pcr0: ("a" * 96), pcr8: ("c" * 96)}, {enclave_id: 1, pcr0: ("b" * 96), pcr8: ("c" * 96)}]
    | map(. + {kms_key_arn: $arn, aws_region: "us-east-1", kms_endpoint: "https://kms.us-east-1.amazonaws.com/"})
' > "$KEYMELD_EIF_MANIFEST"
bash "$keymeld_root/scripts/render-locked-kms-policy.sh" "$KEYMELD_KMS_ROLE_ARN" "$KEYMELD_EIF_MANIFEST" > "$keymeld_test_dir/policy.json"
run_helper
grep -q 'PCR8-only client trust verifies the signer' "$keymeld_test_dir/output"
KEYMELD_ENCLAVE_PCR0="$(printf 'a%.0s' {1..96})"
expect_failure incompatible-shared-pcr0
KEYMELD_ENCLAVE_PCR0=''
export KEYMELD_MOCK_MODE=cargo-failure
if run_helper; then echo "Ignored a Rust test failure." >&2; exit 1; fi
[[ "$(wc -l < "$keymeld_test_dir/cargo.log")" == 1 ]]
for KEYMELD_MOCK_MODE in zero-tests renamed-test; do
    export KEYMELD_MOCK_MODE
    if run_helper; then echo "Accepted an empty or incorrect Rust test selection." >&2; exit 1; fi
    [[ "$(wc -l < "$keymeld_test_dir/cargo.log")" == 1 ]]
done
echo "Nitro KMS acceptance helper mock regressions passed; no AWS calls were made."
