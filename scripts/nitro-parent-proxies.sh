#!/usr/bin/env bash
# Run on the EC2 parent. Both destinations are fixed; KMS TLS passes through intact.
set -euo pipefail

if [[ "${1:-}" == --help ]]; then
    echo "Usage: nitro-parent-proxies.sh [KMS-key-ARN]"
    echo "Without an argument, uses ENCLAVE_KMS_KEY_ID. Runs both proxies in the foreground."
    exit 0
fi
(( $# <= 1 )) || { echo "Expected at most one KMS key ARN." >&2; exit 1; }
key_arn="${1:-${ENCLAVE_KMS_KEY_ID:?Provide the enclave pinned KMS key ARN}}"
arn_pattern='^arn:(aws|aws-us-gov|aws-cn):kms:([a-z0-9-]+):[0-9]{12}:key/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|mrk-[0-9a-fA-F]{32})$'
[[ "$key_arn" =~ $arn_pattern ]] || {
    echo "Parent proxies require a full, immutable KMS key ARN." >&2
    exit 1
}
partition="${BASH_REMATCH[1]}"
arn_region="${BASH_REMATCH[2]}"
[[ "${AWS_REGION:-$arn_region}" == "$arn_region" ]] || {
    echo "AWS_REGION differs from the enclave's KMS key ARN." >&2
    exit 1
}
suffix=amazonaws.com
[[ "$partition" != aws-cn ]] || suffix=amazonaws.com.cn
kms_host="kms.$arn_region.$suffix"

children=()
# shellcheck disable=SC2329 # Invoked by the EXIT trap.
cleanup() {
    trap - EXIT INT TERM
    local pid _ running
    for pid in "${children[@]}"; do
        kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    done
    for _ in {1..20}; do
        running=false
        for pid in "${children[@]}"; do
            if kill -0 -- "-$pid" 2>/dev/null; then running=true; fi
        done
        [[ "$running" == true ]] || break
        sleep 0.05
    done
    for pid in "${children[@]}"; do
        kill -KILL -- "-$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
}
trap 'cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "Relaying enclave KMS TLS to $kms_host:443 and IMDSv2 to the parent metadata service."
setsid socat 'VSOCK-LISTEN:8000,reuseaddr,fork' "TCP4-CONNECT:$kms_host:443" &
children+=("$!")
setsid socat 'VSOCK-LISTEN:8001,reuseaddr,fork' 'TCP4-CONNECT:169.254.169.254:80' &
children+=("$!")
status=0
wait -n "${children[@]}" || status=$?
echo "A parent proxy exited; stopping both proxies." >&2
(( status != 0 )) || status=1
exit "$status"
