#!/usr/bin/env bash
# Manual acceptance against an existing, dedicated AWS deployment. Never deploys
# or changes KMS policy. The Rust tests create and delete synthetic gateway keys.
set -euo pipefail

if [[ "${1:-}" == --help ]]; then
    cat <<'USAGE'
Usage: scripts/test-nitro-kms-e2e.sh
Required environment:
  KEYMELD_KMS_KEY_ARN        Dedicated, locked KMS key ARN
  KEYMELD_KMS_ROLE_ARN       IAM role used by the parent and allowed by the policy
  KEYMELD_EIF_MANIFEST       Reviewed EIF manifest object or array of manifests
  KEYMELD_TEST_GATEWAY_URL   Existing dedicated gateway URL, with HTTPS
  KEYMELD_ENCLAVE_PCR0 and/or KEYMELD_ENCLAVE_PCR8
                            Trusted measurements shared by the selected images
Optional:
  KEYMELD_ENCRYPTED_DEK_FILE Raw encrypted DEK for a no-Recipient Decrypt probe
                            (enclave_id comes from the first manifest)
AWS CLI credentials must already identify the allowed role. Requires aws, jq,
cargo, and an existing real Nitro deployment. Does not start or restart services.
USAGE
    exit 0
fi
(( $# == 0 )) || { echo "Unexpected arguments; use --help." >&2; exit 2; }

fail() { echo "Nitro KMS acceptance failed: $*" >&2; exit 1; }
keymeld_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
key_arn="${KEYMELD_KMS_KEY_ARN:?Set KEYMELD_KMS_KEY_ARN to a dedicated locked key}"
role_arn="${KEYMELD_KMS_ROLE_ARN:?Set KEYMELD_KMS_ROLE_ARN}"
manifest="${KEYMELD_EIF_MANIFEST:?Set KEYMELD_EIF_MANIFEST}"
gateway="${KEYMELD_TEST_GATEWAY_URL:?Set KEYMELD_TEST_GATEWAY_URL}"
[[ "${KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES:-false}" == false ]] ||
    fail "Simulation trust bypass must be unset or false."
export KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES=false
[[ "$gateway" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[^[:space:]?#]*)?$ ]] ||
    fail "Gateway must be an HTTPS URL without credentials, query, or fragment."

arn_pattern='^arn:(aws|aws-us-gov|aws-cn):kms:([a-z0-9-]+):([0-9]{12}):key/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|mrk-[0-9a-fA-F]{32})$'
[[ "$key_arn" =~ $arn_pattern ]] || fail "Expected a full, immutable KMS key ARN."
partition="${BASH_REMATCH[1]}"
region="${BASH_REMATCH[2]}"
account="${BASH_REMATCH[3]}"
[[ "${AWS_REGION:-$region}" == "$region" && "${AWS_DEFAULT_REGION:-$region}" == "$region" ]] ||
    fail "AWS region differs from the KMS key ARN."
role_pattern="^arn:$partition:iam::$account:role/[A-Za-z0-9_+=,.@/-]+$"
[[ "$role_arn" =~ $role_pattern && "$role_arn" != */ ]] ||
    fail "Expected a specific IAM role in the KMS key's partition and account."
for variable in AWS_ENDPOINT_URL AWS_ENDPOINT_URL_KMS AWS_ENDPOINT_URL_STS; do
    [[ -z "${!variable:-}" ]] || fail "Unset $variable; this test uses regional AWS endpoints."
done
suffix=amazonaws.com
[[ "$partition" != aws-cn ]] || suffix=amazonaws.com.cn
kms_endpoint="https://kms.$region.$suffix"
sts_endpoint="https://sts.$region.$suffix"
export AWS_REGION="$region" AWS_DEFAULT_REGION="$region" AWS_PAGER='' AWS_CLI_AUTO_PROMPT=off
for command in aws jq cargo; do
    command -v "$command" >/dev/null || fail "Required command is missing: $command."
done

umask 077
keymeld_test_dir="$(mktemp -d)"
trap 'rm -rf -- "$keymeld_test_dir"' EXIT
jq -ce 'if type == "object" then [.] else . end' "$manifest" > "$keymeld_test_dir/images.json" ||
    fail "Cannot read the reviewed EIF manifest."
bash "$keymeld_root/scripts/render-locked-kms-policy.sh" "$role_arn" "$keymeld_test_dir/images.json" \
    > "$keymeld_test_dir/expected-policy.json"
jq -e --arg arn "$key_arn" --arg region "$region" --arg endpoint "$kms_endpoint" '
    all(.[]; .kms_key_arn == $arn and .aws_region == $region
        and (.kms_endpoint == "aws-kms" or .kms_endpoint == $endpoint or .kms_endpoint == ($endpoint + "/")))
' "$keymeld_test_dir/images.json" >/dev/null ||
    fail "Every reviewed manifest must pin this KMS key ARN, region, and regional AWS endpoint."
measurement_count=0
for index in 0 8; do
    variable="KEYMELD_ENCLAVE_PCR$index"
    measurement="${!variable:-}"
    [[ -n "$measurement" ]] || continue
    [[ "$measurement" =~ ^[0-9a-fA-F]{96}$ && "$measurement" =~ [1-9a-fA-F] ]] ||
        fail "$variable must be a nonzero 96-character hex measurement."
    jq -e --arg name "pcr$index" --arg measurement "${measurement,,}" \
        'all(.[]; (.[$name] | type == "string") and (.[$name] | ascii_downcase) == $measurement)' \
        "$keymeld_test_dir/images.json" >/dev/null ||
        fail "$variable must match every selected image; distinct PCR0 images need a shared trusted PCR8."
    measurement_count=$((measurement_count + 1))
done
(( measurement_count > 0 )) || fail "Set a trusted KEYMELD_ENCLAVE_PCR0 and/or KEYMELD_ENCLAVE_PCR8."
enclave_id="$(jq -r '.[0].enclave_id' "$keymeld_test_dir/images.json")"
if [[ -n "${KEYMELD_ENCRYPTED_DEK_FILE:-}" ]]; then
    [[ -f "$KEYMELD_ENCRYPTED_DEK_FILE" && -r "$KEYMELD_ENCRYPTED_DEK_FILE" && -s "$KEYMELD_ENCRYPTED_DEK_FILE" ]] ||
        fail "KEYMELD_ENCRYPTED_DEK_FILE must be a readable, nonempty ciphertext file."
fi

# Explicit endpoints also override endpoint settings in the AWS CLI profile.
aws_kms() { env -u LD_LIBRARY_PATH aws kms "$@" --region "$region" --endpoint-url "$kms_endpoint"; }
echo "Checking AWS caller, dedicated KMS key, exact locked policy, and absence of grants."
env -u LD_LIBRARY_PATH aws sts get-caller-identity --region "$region" --endpoint-url "$sts_endpoint" --output json \
    > "$keymeld_test_dir/identity.json" || fail "Cannot identify AWS caller."
caller_arn="$(jq -er --arg account "$account" 'select(.Account == $account) | .Arn' "$keymeld_test_dir/identity.json")" ||
    fail "AWS caller belongs to another account."
# STS session ARNs omit the IAM path. Role names are unique within an account.
role_name="${role_arn##*/}"
caller_prefix="arn:$partition:sts::$account:assumed-role/$role_name/"
[[ "$caller_arn" == "$caller_prefix"* && "${caller_arn#"$caller_prefix"}" != '' && "${caller_arn#"$caller_prefix"}" != */* ]] ||
    fail "AWS credentials must belong to the allowed IAM role."
aws_kms describe-key --key-id "$key_arn" --output json > "$keymeld_test_dir/key.json" ||
    fail "DescribeKey failed."
jq -e --arg arn "$key_arn" '.KeyMetadata | .Arn == $arn and .Enabled == true
    and .KeyState == "Enabled" and .KeySpec == "SYMMETRIC_DEFAULT"
    and .KeyUsage == "ENCRYPT_DECRYPT" and .Origin == "AWS_KMS"
    and .KeyManager == "CUSTOMER" and .MultiRegion == false' "$keymeld_test_dir/key.json" >/dev/null ||
    fail "Expected an enabled, symmetric, AWS-origin, single-region customer key."
aws_kms get-key-policy --key-id "$key_arn" --policy-name default --output json \
    > "$keymeld_test_dir/policy-response.json" || fail "GetKeyPolicy failed."
jq -e --slurpfile expected "$keymeld_test_dir/expected-policy.json" \
    '(.Policy | fromjson) == $expected[0]' "$keymeld_test_dir/policy-response.json" >/dev/null ||
    fail "The deployed key policy differs from the reviewed locked template."
# AWS CLI follows ListGrants pagination by default; do not add --no-paginate.
aws_kms list-grants --key-id "$key_arn" --output json > "$keymeld_test_dir/grants.json" ||
    fail "ListGrants failed."
jq -e '.Grants == [] and (.NextMarker == null) and (.Truncated != true)' "$keymeld_test_dir/grants.json" >/dev/null ||
    fail "KMS grants exist or grant enumeration is incomplete."

expect_recipient_denial() {
    local operation="$1" api_operation
    shift
    case "$operation" in
        generate-data-key) api_operation=GenerateDataKey ;;
        decrypt) api_operation=Decrypt ;;
        *) fail "Unsupported negative probe." ;;
    esac
    # Filter any accidental success to KeyId at the CLI boundary. Never display
    # plaintext, ciphertext, or raw command output, including on failure.
    if aws_kms "$operation" --key-id "$key_arn" --encryption-context "enclave_id=$enclave_id" \
        "$@" --query KeyId --output text > /dev/null 2> "$keymeld_test_dir/denial.txt"; then
        fail "$operation without Recipient unexpectedly succeeded."
    fi
    if ! LC_ALL=C grep -Eq "An error occurred \(AccessDenied(Exception)?\) when calling the $api_operation operation:" "$keymeld_test_dir/denial.txt"; then
        fail "$operation did not return AccessDenied; transport and other errors do not prove the policy."
    fi
    echo "Confirmed parent $operation without Recipient is denied."
}
expect_recipient_denial generate-data-key --key-spec AES_256
if [[ -n "${KEYMELD_ENCRYPTED_DEK_FILE:-}" ]]; then
    expect_recipient_denial decrypt --ciphertext-blob "fileb://$KEYMELD_ENCRYPTED_DEK_FILE"
else
    echo "Ordinary Decrypt negative probe skipped: no encrypted DEK file supplied."
fi

echo "Running measured-client approval and key-lifecycle tests against the existing HTTPS gateway."
export RUSTC_WRAPPER='' CARGO_INCREMENTAL=0
cd -- "$keymeld_root"
run_acceptance_test() {
    local target="$1" test_name="$2"
    # libtest returns success for an empty --exact selection after a rename.
    cargo test -p keymeld-examples --locked --test "$target" -- \
        --ignored --exact "$test_name" --list > "$keymeld_test_dir/test-list.txt"
    if [[ "$(grep -c ': test$' "$keymeld_test_dir/test-list.txt")" != 1 ]] ||
        ! grep -Fxq "$test_name: test" "$keymeld_test_dir/test-list.txt"; then
        fail "Expected exactly the named ignored test in $target; refusing an empty or changed selection."
    fi
    cargo test -p keymeld-examples --locked --test "$target" -- \
        --ignored --exact "$test_name" --nocapture
}
run_acceptance_test approval_binding required_approvals_bind_the_reviewed_complete_batch
run_acceptance_test key_lifecycle key_lifecycle_authentication_and_ciphertext_transplant_attacks
echo "Nitro KMS acceptance subset passed."
if [[ -z "${KEYMELD_ENCLAVE_PCR0:-}" ]]; then
    echo "PCR8-only client trust verifies the signer; correlate CloudTrail image digests with the reviewed PCR0 values and this KMS key."
fi
echo "Hardware matrix remains incomplete: debug/foreign-PCR denial and full enclave restart recovery require the manual checks in docs/KMS.md."
