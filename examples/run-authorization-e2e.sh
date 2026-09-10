#!/usr/bin/env bash
# Run real gateway/enclave authorization regressions with synthetic keys.
# Usage: nix develop -c bash examples/run-authorization-e2e.sh [--skip-build]
set -euo pipefail

test_repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$test_repository"

# The repository enables incremental compilation, which conflicts with the
# Nix shell's sccache wrapper. Use ordinary rustc for this reproducible test run.
export RUSTC_WRAPPER= CARGO_INCREMENTAL=0

for test_command in cargo moto_server aws jq curl ss sqlite3; do
    if ! command -v "$test_command" >/dev/null; then
        echo "$test_command is required. Run this script inside nix develop." >&2
        exit 1
    fi
done

if [[ "${1:-}" != "--skip-build" ]]; then
    cargo build --bin keymeld-gateway --bin keymeld-enclave
    cargo test -p keymeld-examples --test authorization --test approval_binding --test key_lifecycle --no-run
    cargo test -p keymeld-enclave --test kms_key_pinning --no-run
fi
test_target=$(cargo metadata --format-version 1 --no-deps | jq -r '.target_directory')
test_binary_directory="$test_target/debug"
for test_binary in keymeld-gateway keymeld-enclave; do
    if [[ ! -x "$test_binary_directory/$test_binary" ]]; then
        echo "Missing $test_binary_directory/$test_binary; omit --skip-build." >&2
        exit 1
    fi
done

# This runner owns every process and file it creates. Existing development
# services and databases remain available while these tests run.
test_directory=$(mktemp -d -t keymeld-authorization-e2e.XXXXXXXX)
test_pids=()
test_succeeded=false
cleanup() {
    local test_exit_status=$?
    trap - EXIT INT TERM
    for test_pid in "${test_pids[@]}"; do
        kill "$test_pid" 2>/dev/null || true
    done
    for test_pid in "${test_pids[@]}"; do
        wait "$test_pid" 2>/dev/null || true
    done
    if [[ "$test_succeeded" == true ]]; then
        find "$test_directory" -depth -delete
    else
        echo "Authorization E2E failed. Logs and temporary database: $test_directory" >&2
        for test_log in "$test_directory"/*.log; do
            [[ -f "$test_log" ]] || continue
            echo "Last lines of $test_log:" >&2
            tail -n 25 "$test_log" >&2
        done
    fi
    exit "$test_exit_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

test_port_base=0
for ((test_attempt = 0; test_attempt < 40; test_attempt++)); do
    test_candidate=$((20000 + RANDOM % 30000))
    test_ports_available=true
    for ((test_offset = 0; test_offset < 5; test_offset++)); do
        if [[ -n "$(ss -H -ltn "sport = :$((test_candidate + test_offset))")" ]]; then
            test_ports_available=false
            break
        fi
    done
    if [[ "$test_ports_available" == true ]]; then
        test_port_base=$test_candidate
        break
    fi
done
if [[ "$test_port_base" == 0 ]]; then
    echo "Could not find five unused TCP ports." >&2
    exit 1
fi
test_gateway_url="http://127.0.0.1:$test_port_base"
test_kms_port=$((test_port_base + 1))
test_kms_url="http://127.0.0.1:$test_kms_port"

# Prevent inherited service configuration from redirecting this isolated run.
for test_variable in ${!KEYMELD_@}; do unset "$test_variable"; done
unset AWS_PROFILE AWS_SESSION_TOKEN AWS_ENDPOINT_URL AWS_ENDPOINT_URL_KMS
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-west-2 AWS_REGION=us-west-2 AWS_EC2_METADATA_DISABLED=true
export KEYMELD_ENVIRONMENT=development RUST_LOG=info
export KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES=true
export KEYMELD_GATEWAY_SIGNING_KEY_FILE="$test_directory/gateway-channel.key"
export ENCLAVE_GATEWAY_PUBLIC_KEY
ENCLAVE_GATEWAY_PUBLIC_KEY=$(LD_LIBRARY_PATH="${CMAKE_LIBRARY_PATH:-}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$test_binary_directory/keymeld-gateway" --generate-channel-key "$KEYMELD_GATEWAY_SIGNING_KEY_FILE")
test_service_library_path="${CMAKE_LIBRARY_PATH:-}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

wait_for_http() {
    local test_url=$1
    local test_attempt test_pid
    for ((test_attempt = 0; test_attempt < 180; test_attempt++)); do
        for test_pid in "${test_pids[@]}"; do
            if ! kill -0 "$test_pid" 2>/dev/null; then
                echo "An E2E service exited before $test_url became available." >&2
                return 1
            fi
        done
        if curl --max-time 1 -fsS "$test_url" >/dev/null 2>&1; then return 0; fi
        sleep 0.25
    done
    echo "Timed out waiting for $test_url." >&2
    return 1
}

echo "Authorization E2E diagnostics: $test_directory"
env -u LD_LIBRARY_PATH moto_server -H 127.0.0.1 -p "$test_kms_port" >"$test_directory/moto.log" 2>&1 &
test_moto_pid=$!
test_pids+=("$test_moto_pid")
wait_for_http "$test_kms_url"
test_kms_key=$(env -u LD_LIBRARY_PATH aws --endpoint-url "$test_kms_url" kms create-key \
    --description 'Keymeld authorization regression test' --query KeyMetadata.KeyId --output text)
export ENCLAVE_KMS_ENDPOINT="$test_kms_url" ENCLAVE_KMS_KEY_ID="$test_kms_key"

cat >"$test_directory/config.yaml" <<EOF
environment: development
server:
  host: "127.0.0.1"
  port: $test_port_base
  enable_cors: false
  enable_compression: true
kms:
  enabled: true
  endpoint_url: "$test_kms_url"
  key_id: "$test_kms_key"
database:
  path: "$test_directory/keymeld.sqlite"
  max_connections: 10
  connection_timeout_secs: 30
  idle_timeout_secs: 60
  enable_wal_mode: true
enclaves:
  enclaves:
    - { id: 0, cid: 2, port: $((test_port_base + 2)), transport: tcp, tcp_host: "127.0.0.1" }
    - { id: 1, cid: 2, port: $((test_port_base + 3)), transport: tcp, tcp_host: "127.0.0.1" }
    - { id: 2, cid: 2, port: $((test_port_base + 4)), transport: tcp, tcp_host: "127.0.0.1" }
coordinator:
  processing_interval_ms: 50
  health_check_interval_secs: 2
logging:
  level: info
  format: pretty
  enable_json: false
  enable_file_output: false
  file_path: null
security:
  enable_attestation: false
  strict_validation: false
  allow_insecure_connections: true
  require_tls: false
development:
  enable_test_endpoints: false
  disable_enclave_verification: true
  extended_logging: false
EOF

start_keymeld_services() {
    local test_log_suffix=$1
    for ((test_enclave_id = 0; test_enclave_id < 3; test_enclave_id++)); do
        ENCLAVE_ID="$test_enclave_id" VSOCK_PORT=$((test_port_base + 2 + test_enclave_id)) \
            TRANSPORT_MODE=tcp TCP_HOST=127.0.0.1 \
            LD_LIBRARY_PATH="$test_service_library_path" \
            "$test_binary_directory/keymeld-enclave" \
            >"$test_directory/enclave-$test_enclave_id$test_log_suffix.log" 2>&1 &
        test_pids+=("$!")
    done
    CONFIG_PATH="$test_directory/config.yaml" LD_LIBRARY_PATH="$test_service_library_path" \
        "$test_binary_directory/keymeld-gateway" >"$test_directory/gateway$test_log_suffix.log" 2>&1 &
    test_gateway_pid=$!
    test_pids+=("$test_gateway_pid")
    wait_for_http "$test_gateway_url/api/v1/health"
    for ((test_enclave_id = 0; test_enclave_id < 3; test_enclave_id++)); do
        wait_for_http "$test_gateway_url/api/v1/enclaves/$test_enclave_id/public-key"
    done
}
start_keymeld_services ""

export KEYMELD_TEST_GATEWAY_URL="$test_gateway_url"
export KEYMELD_TEST_ENCLAVE_PORT_BASE=$((test_port_base + 2))
export KEYMELD_TEST_RESTART_STATE_PATH="$test_directory/restart-fixture.json"
cargo test -p keymeld-examples \
    --test authorization --test approval_binding --test key_lifecycle \
    -- --ignored --nocapture --skip signing_after_enclave_restart

echo "Restarting only the gateway while all three enclaves retain their configured keys"
kill "$test_gateway_pid"
wait "$test_gateway_pid" 2>/dev/null || true
unset 'test_pids[${#test_pids[@]}-1]'
CONFIG_PATH="$test_directory/config.yaml" LD_LIBRARY_PATH="$test_service_library_path" \
    "$test_binary_directory/keymeld-gateway" >"$test_directory/gateway-only-restarted.log" 2>&1 &
test_gateway_pid=$!
test_pids+=("$test_gateway_pid")
wait_for_http "$test_gateway_url/api/v1/health"
cargo test -p keymeld-examples --test authorization signing_after_enclave_restart \
    -- --ignored --nocapture

echo "Restarting gateway and all three enclaves with the same database and KMS keys"
for test_pid in "${test_pids[@]:1}"; do kill "$test_pid" 2>/dev/null || true; done
for test_pid in "${test_pids[@]:1}"; do wait "$test_pid" 2>/dev/null || true; done
test_pids=("$test_moto_pid")
start_keymeld_services "-restarted"
cargo test -p keymeld-examples --test authorization signing_after_enclave_restart \
    -- --ignored --nocapture

# Rejected registrations and competing claims must not leave encrypted key rows
# behind. Every synthetic key in this isolated run belongs to one claimed slot.
test_orphan_count=$(sqlite3 "$test_directory/keymeld.sqlite" \
    'SELECT COUNT(*) FROM user_keys uk LEFT JOIN keygen_participants kp ON kp.user_key_id = uk.id WHERE kp.user_key_id IS NULL;')
if [[ "$test_orphan_count" != 0 ]]; then
    echo "Rejected registration left $test_orphan_count orphan encrypted key rows." >&2
    exit 1
fi
test_duplicate_count=$(sqlite3 "$test_directory/keymeld.sqlite" \
    'SELECT COUNT(*) FROM (SELECT keygen_session_id, user_id FROM keygen_participants GROUP BY keygen_session_id, user_id HAVING COUNT(*) > 1);')
if [[ "$test_duplicate_count" != 0 ]]; then
    echo "Concurrent registration created duplicate participant slots." >&2
    exit 1
fi
echo "PASS database contains no orphan key rows or duplicate participant slots"
test_succeeded=true
