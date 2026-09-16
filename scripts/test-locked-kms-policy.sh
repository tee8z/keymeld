#!/usr/bin/env bash
set -euo pipefail
keymeld_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
keymeld_test_dir="$(mktemp -d)"
trap 'rm -rf -- "$keymeld_test_dir"' EXIT
keymeld_role=arn:aws:iam::123456789012:role/keymeld-enclave
jq -n '[{enclave_id: 0, pcr0: ("a" * 96)}, {enclave_id: 1, pcr0: ("b" * 96)}]' > "$keymeld_test_dir/images.json"
bash "$keymeld_root/scripts/render-locked-kms-policy.sh" "$keymeld_role" "$keymeld_test_dir/images.json" > "$keymeld_test_dir/policy.json"
jq -e --arg role "$keymeld_role" '
  (.Statement | length == 5)
  and all(.Statement[] | select(.Effect == "Allow"); .Principal.AWS == $role)
  and any(.Statement[]; .Sid == "DenyAdministrationAndOtherCryptography"
    and .Effect == "Deny" and .Principal == "*"
    and (.NotAction | sort) == (["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListGrants"] | sort))
  and any(.Statement[]; .Sid == "DenyMissingOrUnapprovedAttestation"
    and .Condition.StringNotEqualsIgnoreCase["kms:RecipientAttestation:ImageSha384"] == [("a" * 96), ("b" * 96)])
' "$keymeld_test_dir/policy.json" >/dev/null
for keymeld_bad in '[]' '[{"enclave_id":0,"pcr0":"*"}]' \
    '[{"enclave_id":0,"pcr0":("0" * 96)}]' \
    '[{"enclave_id":0,"pcr0":("a" * 96)},{"enclave_id":0,"pcr0":("b" * 96)}]'; do
    jq -n "$keymeld_bad" > "$keymeld_test_dir/bad.json"
    if bash "$keymeld_root/scripts/render-locked-kms-policy.sh" "$keymeld_role" "$keymeld_test_dir/bad.json" >/dev/null 2>&1; then
        echo "Unsafe manifest accepted: $keymeld_bad" >&2; exit 1
    fi
done
if bash "$keymeld_root/scripts/render-locked-kms-policy.sh" arn:aws:iam::123456789012:root "$keymeld_test_dir/images.json" >/dev/null 2>&1; then
    echo "Account-root principal accepted" >&2; exit 1
fi
echo "Locked KMS policy renderer regressions passed."
