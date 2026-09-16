#!/usr/bin/env bash
# Runs inside the measured EIF. The parent relays bytes; TLS ends in the enclave.
set -euo pipefail

if (( $# == 0 )); then
    set -- /bin/keymeld-enclave
fi
if [[ "${TRANSPORT_MODE:-vsock}" == tcp ]]; then
    exec "$@"
fi
[[ "${TRANSPORT_MODE:-vsock}" == vsock ]] || {
    echo "Nitro entrypoint requires TRANSPORT_MODE=vsock or tcp." >&2
    exit 1
}
[[ "${KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES:-false}" == false ]] || {
    echo "Nitro startup refuses unattested development mode." >&2
    exit 1
}
export KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES=false

key_arn="${ENCLAVE_KMS_KEY_ID:?Bake ENCLAVE_KMS_KEY_ID into the enclave image}"
arn_pattern='^arn:(aws|aws-us-gov|aws-cn):kms:([a-z0-9-]+):[0-9]{12}:key/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|mrk-[0-9a-fA-F]{32})$'
[[ "$key_arn" =~ $arn_pattern ]] || {
    echo "Nitro startup requires a full, immutable KMS key ARN." >&2
    exit 1
}
partition="${BASH_REMATCH[1]}"
arn_region="${BASH_REMATCH[2]}"
[[ "${AWS_REGION:-$arn_region}" == "$arn_region" ]] || {
    echo "AWS_REGION differs from the measured KMS key ARN." >&2
    exit 1
}
suffix=amazonaws.com
[[ "$partition" != aws-cn ]] || suffix=amazonaws.com.cn
kms_host="kms.$arn_region.$suffix"
case "${ENCLAVE_KMS_ENDPOINT:-aws-kms}" in
    aws-kms|"https://$kms_host"|"https://$kms_host/") ;;
    *) echo "Nitro startup refuses a nonregional AWS KMS endpoint." >&2; exit 1 ;;
esac
export AWS_REGION="$arn_region"

# The default AWS credential provider refreshes the instance role through IMDSv2.
# The parent proxy has a fixed IMDS destination and does not store credentials.
export AWS_EC2_METADATA_SERVICE_ENDPOINT=http://127.0.0.1:8001
export AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE=IPv4
export AWS_EC2_METADATA_V1_DISABLED=true
export AWS_EC2_METADATA_DISABLED=false

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

ip link set lo up
# A dedicated enclave needs only localhost and the pinned regional KMS hostname.
# Keep the URL hostname intact so the AWS client verifies the KMS TLS certificate.
printf '127.0.0.1 localhost\n127.0.0.1 %s\n' "$kms_host" | tee /etc/hosts >/dev/null

setsid socat 'TCP4-LISTEN:443,bind=127.0.0.1,reuseaddr,fork' 'VSOCK-CONNECT:3:8000' &
children+=("$!")
setsid socat 'TCP4-LISTEN:8001,bind=127.0.0.1,reuseaddr,fork' 'VSOCK-CONNECT:3:8001' &
children+=("$!")

wait_for_listener() {
    local port="$1" pid="$2" _ listeners address
    for _ in {1..100}; do
        kill -0 "$pid" 2>/dev/null || {
            echo "Nitro bridge on port $port exited during startup." >&2
            return 1
        }
        listeners="$(ss -H -ltn "sport = :$port")"
        while read -r _ _ _ address _; do
            if [[ "$address" == "127.0.0.1:$port" ]]; then return 0; fi
        done <<< "$listeners"
        sleep 0.05
    done
    echo "Nitro bridge on port $port did not start listening." >&2
    return 1
}
wait_for_listener 443 "${children[0]}"
wait_for_listener 8001 "${children[1]}"

setsid "$@" &
children+=("$!")
status=0
wait -n "${children[@]}" || status=$?
echo "An enclave or bridge process exited; stopping the Nitro runtime." >&2
(( status != 0 )) || status=1
exit "$status"
