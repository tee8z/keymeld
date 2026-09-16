#!/usr/bin/env bash
# Mock network commands: no /etc/hosts writes, interface changes, or vsock access.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
scratch="$(mktemp -d -t keymeld-nitro-test.XXXXXXXX)"
driver_pid=
cleanup() {
    if [[ -n "$driver_pid" ]]; then
        kill -TERM "$driver_pid" 2>/dev/null || true
        wait "$driver_pid" 2>/dev/null || true
    fi
    rm -rf -- "$scratch"
}
trap 'cleanup' EXIT
mkdir "$scratch/bin"

cat > "$scratch/bin/ip" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$TEST_ROOT/ip.args"
EOF
cat > "$scratch/bin/tee" <<'EOF'
#!/usr/bin/env bash
[[ "$*" == /etc/hosts ]] || exit 80
cat > "$TEST_ROOT/hosts"
EOF
cat > "$scratch/bin/ss" <<'EOF'
#!/usr/bin/env bash
for port in 443 8001; do
    if [[ "$*" == *":$port"* && -f "$TEST_ROOT/listener.$port" ]]; then
        printf 'LISTEN 0 128 127.0.0.1:%s 0.0.0.0:*\n' "$port"
    fi
done
EOF
cat > "$scratch/bin/socat" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
    TCP4-LISTEN:443,*) role=enclave-kms; port=443 ;;
    TCP4-LISTEN:8001,*) role=enclave-imds; port=8001 ;;
    VSOCK-LISTEN:8000,*) role=parent-kms; port=8000 ;;
    VSOCK-LISTEN:8001,*) role=parent-imds; port=8001 ;;
    *) exit 81 ;;
esac
printf '%s\n' "$*" > "$TEST_ROOT/$role.args"
printf '%s\n' "$$" > "$TEST_ROOT/$role.pid"
if [[ "${FAIL_BRIDGE:-}" == "$role" ]]; then exit 42; fi
touch "$TEST_ROOT/listener.$port"
trap 'exit 0' TERM INT
while :; do sleep 1; done
EOF
cat > "$scratch/bin/enclave" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$$" > "$TEST_ROOT/enclave.pid"
printf '%s\n' "$*" > "$TEST_ROOT/enclave.args"
printf '%s\n' "${AWS_EC2_METADATA_SERVICE_ENDPOINT:-unset}" > "$TEST_ROOT/imds.endpoint"
printf '%s\n' "${AWS_EC2_METADATA_V1_DISABLED:-unset}" > "$TEST_ROOT/imds.v1_disabled"
touch "$TEST_ROOT/enclave.ready"
if [[ "${ENCLAVE_EXITS:-false}" == true ]]; then exit 7; fi
trap 'exit 0' TERM INT
while :; do sleep 1; done
EOF
chmod +x "$scratch/bin/"*

key='arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789abc'
test_path="$scratch/bin:$PATH"
new_case() {
    case_dir="$scratch/$1"
    mkdir "$case_dir"
}
start_case() {
    env PATH="$test_path" TEST_ROOT="$case_dir" ENCLAVE_KMS_KEY_ID="$key" \
        ENCLAVE_KMS_ENDPOINT=aws-kms AWS_REGION=us-west-2 TRANSPORT_MODE=vsock \
        KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES=false \
        "$@" > "$case_dir/output" 2>&1 &
    driver_pid=$!
}
wait_for_file() {
    local filename="$1" _
    for _ in {1..200}; do
        [[ ! -f "$filename" ]] || return 0
        if ! kill -0 "$driver_pid" 2>/dev/null; then break; fi
        sleep 0.025
    done
    cat "$case_dir/output" >&2
    echo "Expected file did not appear: $filename" >&2
    return 1
}
wait_for_exit() {
    local expected="$1" status=0 _
    for _ in {1..200}; do
        if ! kill -0 "$driver_pid" 2>/dev/null; then break; fi
        sleep 0.025
    done
    if kill -0 "$driver_pid" 2>/dev/null; then
        echo "Driver did not exit." >&2
        return 1
    fi
    wait "$driver_pid" || status=$?
    driver_pid=
    [[ "$status" == "$expected" ]] || {
        cat "$case_dir/output" >&2
        echo "Expected exit $expected, got $status." >&2
        return 1
    }
    local file pid
    for file in "$case_dir/"*.pid; do
        [[ -f "$file" ]] || continue
        read -r pid < "$file"
        if kill -0 "$pid" 2>/dev/null; then
            echo "Child process survived cleanup: $file ($pid)." >&2
            return 1
        fi
    done
}

new_case enclave_success
start_case bash "$script_dir/nitro-entrypoint.sh" "$scratch/bin/enclave" --example-argument
wait_for_file "$case_dir/enclave.ready"
[[ "$(cat "$case_dir/enclave-kms.args")" == 'TCP4-LISTEN:443,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:3:8000' ]]
[[ "$(cat "$case_dir/enclave-imds.args")" == 'TCP4-LISTEN:8001,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:3:8001' ]]
[[ "$(cat "$case_dir/hosts")" == $'127.0.0.1 localhost\n127.0.0.1 kms.us-west-2.amazonaws.com' ]]
[[ "$(cat "$case_dir/imds.endpoint")" == http://127.0.0.1:8001 ]]
[[ "$(cat "$case_dir/imds.v1_disabled")" == true ]]
[[ "$(cat "$case_dir/enclave.args")" == --example-argument ]]
kill -TERM "$driver_pid"
wait_for_exit 143

new_case enclave_exits
start_case ENCLAVE_EXITS=true bash "$script_dir/nitro-entrypoint.sh" "$scratch/bin/enclave"
wait_for_exit 7

new_case bridge_fails
start_case FAIL_BRIDGE=enclave-kms bash "$script_dir/nitro-entrypoint.sh" "$scratch/bin/enclave"
wait_for_exit 1
[[ ! -e "$case_dir/enclave.ready" ]]

new_case bridge_exits_after_startup
start_case bash "$script_dir/nitro-entrypoint.sh" "$scratch/bin/enclave"
wait_for_file "$case_dir/enclave.ready"
read -r bridge_pid < "$case_dir/enclave-kms.pid"
kill -TERM "$bridge_pid"
wait_for_exit 1

new_case parent_success
start_case bash "$script_dir/nitro-parent-proxies.sh"
wait_for_file "$case_dir/parent-kms.args"
wait_for_file "$case_dir/parent-imds.args"
[[ "$(cat "$case_dir/parent-kms.args")" == 'VSOCK-LISTEN:8000,reuseaddr,fork TCP4-CONNECT:kms.us-west-2.amazonaws.com:443' ]]
[[ "$(cat "$case_dir/parent-imds.args")" == 'VSOCK-LISTEN:8001,reuseaddr,fork TCP4-CONNECT:169.254.169.254:80' ]]
kill -TERM "$driver_pid"
wait_for_exit 143

new_case parent_fails
start_case FAIL_BRIDGE=parent-kms bash "$script_dir/nitro-parent-proxies.sh"
wait_for_exit 42

new_case china_partition
start_case ENCLAVE_KMS_KEY_ID='arn:aws-cn:kms:cn-north-1:123456789012:key/mrk-11111111111111111111111111111111' \
    AWS_REGION=cn-north-1 bash "$script_dir/nitro-parent-proxies.sh"
wait_for_file "$case_dir/parent-kms.args"
[[ "$(cat "$case_dir/parent-kms.args")" == 'VSOCK-LISTEN:8000,reuseaddr,fork TCP4-CONNECT:kms.cn-north-1.amazonaws.com.cn:443' ]]
kill -TERM "$driver_pid"
wait_for_exit 143

new_case tcp_direct
start_case TRANSPORT_MODE=tcp ENCLAVE_EXITS=true KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES=true \
    bash "$script_dir/nitro-entrypoint.sh" "$scratch/bin/enclave" tcp-argument
wait_for_exit 7
[[ ! -e "$case_dir/enclave-kms.args" && ! -e "$case_dir/hosts" ]]
[[ "$(cat "$case_dir/enclave.args")" == tcp-argument ]]

for invalid in \
    'ENCLAVE_KMS_KEY_ID=alias/unpinned' \
    'AWS_REGION=us-east-1' \
    'ENCLAVE_KMS_ENDPOINT=https://attacker.test' \
    'KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES=true'; do
    new_case "invalid_${invalid%%=*}"
    start_case "$invalid" bash "$script_dir/nitro-entrypoint.sh" "$scratch/bin/enclave"
    wait_for_exit 1
    [[ ! -e "$case_dir/ip.args" && ! -e "$case_dir/enclave.ready" ]]
done

new_case parent_invalid
start_case bash "$script_dir/nitro-parent-proxies.sh" 'https://attacker.test'
wait_for_exit 1
[[ ! -e "$case_dir/parent-kms.args" ]]
echo "Nitro bridge tests passed."
