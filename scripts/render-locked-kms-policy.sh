#!/usr/bin/env bash
# Render only. Never creates a key, changes a policy, or contacts AWS.
set -euo pipefail
if [[ $# != 2 ]]; then
    echo "Usage: $0 ENCLAVE_ROLE_ARN REVIEWED_EIF_MANIFEST_ARRAY" >&2
    exit 2
fi
keymeld_policy_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
keymeld_role="$1"
[[ "$keymeld_role" =~ ^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]+$ ]] || {
    echo "Expected a specific IAM role ARN; root, users, and wildcards are rejected." >&2
    exit 1
}
keymeld_images="$(jq -ce '
    if type != "array" or length == 0 then error("Expected nonempty reviewed manifest array") else . end
    | if all(.[]; (.enclave_id | type == "number" and . >= 0 and . <= 4294967295 and floor == .)
        and (.pcr0 | type == "string" and test("^[0-9a-fA-F]{96}$") and test("[1-9a-fA-F]")))
      then . else error("Invalid enclave ID or PCR0; debug measurements are rejected") end
    | if ([.[].enclave_id] | unique | length) == length then . else error("Duplicate enclave ID") end
    | [.[].pcr0 | ascii_downcase] | unique
' "$2")"
jq -n --arg role "$keymeld_role" --argjson images "$keymeld_images" \
    -f "$keymeld_policy_root/config/kms-locked-policy.jq"
echo "Rendered a locked policy for review only. Applying it removes policy administration and blocks future image changes." >&2
