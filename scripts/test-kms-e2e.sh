#!/usr/bin/env bash
# KMS End-to-End Test with Restart Validation
# Tests KMS initialization, operation, and restart scenarios
#
# This script must be run inside nix develop:
#   nix develop -c ./scripts/test-kms-e2e.sh
# Or via just:
#   just test-kms-e2e
set -euo pipefail

GATEWAY_URL="http://localhost:8090/api/v1"
TEST_AMOUNT=25000
TEST_DEST="bcrt1qf0p0zqynlcq7c4j6vm53qaxapm3chufwfgge80"

# Verify we're running inside nix develop by checking for CMAKE_LIBRARY_PATH
if [ -z "${CMAKE_LIBRARY_PATH:-}" ]; then
    echo "ERROR: This script must be run inside nix develop"
    echo "Usage: nix develop -c ./scripts/test-kms-e2e.sh"
    echo "   Or: just test-kms-e2e"
    exit 1
fi

# Use CMAKE_LIBRARY_PATH for LD_LIBRARY_PATH (set by nix flake)
export LD_LIBRARY_PATH="${CMAKE_LIBRARY_PATH:-}"

# Increase file descriptor limit for high concurrency
ulimit -n 65536 2>/dev/null || true

# Ensure VSock proxies are running (required for enclave communication)
ensure_vsock_proxies() {
    if ! pgrep -f "socat.*vsock-connect" >/dev/null 2>&1; then
        echo "Starting VSock proxies..."
        ./scripts/vsock-setup.sh start >/dev/null 2>&1 || true
        sleep 1
    fi
}

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0

# Cleanup function to stop services on exit
cleanup() {
    echo ""
    echo "🧹 Cleaning up services..."
    # Use pgrep -x to match exact process names, avoiding parent shell matches
    for proc in keymeld-gateway keymeld-enclave keymeld_demo keymeld_session_test; do
        pgrep -x "$proc" 2>/dev/null | xargs -r kill 2>/dev/null || true
    done
    pkill -x moto_server || true
    pkill -x bitcoind || true
}
trap cleanup EXIT

echo "🧪 KeyMeld KMS End-to-End Test Suite"
echo "====================================="
echo ""

# ===========================================
# Phase 0: Build and Start All Services
# ===========================================
echo "📦 Phase 0: Building and Starting Services"
echo "==========================================="

# Clean previous state
echo "🧹 Cleaning previous state..."
./scripts/clean.sh >/dev/null 2>&1 || true
mkdir -p data logs

# Start VSock proxies
echo "🔌 Starting VSock proxies..."
QUIET=true ./scripts/vsock-setup.sh start >/dev/null 2>&1 || true

# Build the project (skip if SKIP_BUILD is set and binaries exist)
if [ -n "${SKIP_BUILD:-}" ] && [ -f "target/debug/keymeld-gateway" ] && [ -f "target/debug/keymeld-enclave" ]; then
    echo "✅ Using pre-built binaries"
else
    echo "🔨 Building KeyMeld..."
    cargo build --quiet 2>&1 || { echo "❌ Build failed"; exit 1; }
    echo "✅ Build complete"
fi

# Start Moto (KMS mock)
echo "🔐 Starting Moto (KMS mock)..."
if ! pgrep -f moto_server > /dev/null; then
    nix run .#localstack > logs/localstack.log 2>&1 &
    sleep 5

    # Create KMS key
    KEY_OUTPUT=$(AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-west-2 \
        aws --endpoint-url=http://localhost:4566 kms create-key \
        --description "KeyMeld Enclave Master Key" \
        --key-usage ENCRYPT_DECRYPT 2>&1)

    if echo "$KEY_OUTPUT" | grep -q "KeyId"; then
        KEY_ID=$(echo "$KEY_OUTPUT" | grep -o '"KeyId": "[^"]*"' | cut -d'"' -f4)
        AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-west-2 \
            aws --endpoint-url=http://localhost:4566 kms create-alias \
            --alias-name alias/keymeld-enclave-master-key \
            --target-key-id "$KEY_ID" 2>&1 || true
        echo "✅ KMS key created: $KEY_ID"
    fi
fi

# Set AWS credentials
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-west-2

# Start Gateway
echo "🌐 Starting Gateway..."
RUST_LOG=info KEYMELD_ENVIRONMENT=development LD_LIBRARY_PATH="${LD_LIBRARY_PATH}" \
    AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-west-2 \
    ./target/debug/keymeld-gateway > logs/gateway.log 2>&1 &

# Start Enclaves
echo "🔒 Starting Enclaves..."
for i in {0..2}; do
    port=$((5000 + i))
    cid=2
    RUST_LOG=info ENCLAVE_ID=${i} ENCLAVE_CID=${cid} VSOCK_PORT=${port} \
        LD_LIBRARY_PATH="${LD_LIBRARY_PATH}" \
        AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-west-2 \
        ./target/debug/keymeld-enclave > logs/enclave-${i}.log 2>&1 &
done

echo ""

# Helper functions
# Log a step success (does not count as a test)
log_step() {
    echo -e "${GREEN}✓${NC} $1"
}

# Log a step failure (does not count as a test)
log_step_error() {
    echo -e "${RED}✗${NC} $1"
}

# Log info
log_info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

# Mark a test phase as passed
test_passed() {
    echo -e "${GREEN}✓${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

# Mark a test phase as failed
test_failed() {
    echo -e "${RED}✗${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

wait_for_service() {
    local service=$1
    local url=$2
    local max_wait=30
    local count=0

    log_info "Waiting for $service to be ready..."
    while [ $count -lt $max_wait ]; do
        if curl -s "$url" >/dev/null 2>&1; then
            log_step "$service is ready"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done

    log_step_error "$service failed to start within ${max_wait}s"
    return 1
}

check_kms_keys_exist() {
    local enclave_id=$1
    log_info "Checking if KMS keys exist for enclave $enclave_id in database..."

    # Query the database to check if keys exist
    if sqlite3 data/keymeld.db "SELECT COUNT(*) FROM enclave_master_keys WHERE enclave_id = $enclave_id;" | grep -q "1"; then
        log_step "KMS keys found in database for enclave $enclave_id"
        return 0
    else
        log_step_error "No KMS keys found in database for enclave $enclave_id"
        return 1
    fi
}

get_key_epoch() {
    local enclave_id=$1
    sqlite3 data/keymeld.db "SELECT key_epoch FROM enclave_master_keys WHERE enclave_id = $enclave_id;" 2>/dev/null || echo "0"
}

check_enclave_initialized() {
    local enclave_id=$1
    log_info "Checking if enclave $enclave_id is initialized..."

    # Check health/detail endpoint for enclave count
    health_response=$(curl -s "$GATEWAY_URL/health/detail" 2>/dev/null || echo "")

    # Check if we have healthy enclaves
    if echo "$health_response" | grep -q "\"healthy_enclaves\""; then
        healthy_count=$(echo "$health_response" | grep -o '"healthy_enclaves":[0-9]*' | cut -d: -f2)
        if [ "$healthy_count" -ge "$((enclave_id + 1))" ]; then
            log_step "Enclave $enclave_id is initialized and responding"
            return 0
        fi
    fi

    log_step_error "Enclave $enclave_id is not initialized"
    return 1
}

# Test 1: Initial KMS Setup
echo "📋 Test 1: Initial KMS Setup and Key Generation"
echo "------------------------------------------------"

if wait_for_service "Gateway" "$GATEWAY_URL/health"; then
    log_step "Gateway is running"
else
    log_step_error "Gateway is not running"
    exit 1
fi

# Check that Moto (KMS mock) is running
if pgrep -f moto_server >/dev/null; then
    log_step "Moto (KMS mock) is running"
else
    log_step_error "Moto (KMS mock) is not running"
    exit 1
fi

# Wait for database migrations and enclave initialization with retries
log_info "Waiting for database migrations and enclave initialization..."
max_retries=60
retry_count=0
all_enclaves_initialized=false

while [ $retry_count -lt $max_retries ]; do
    sleep 1
    retry_count=$((retry_count + 1))

    # Check if database file exists
    if [ ! -f "data/keymeld.db" ]; then
        log_info "Waiting for database file to be created... (attempt $retry_count/$max_retries)"
        continue
    fi

    # Check if migrations have run (keygen_sessions table exists)
    if ! sqlite3 data/keymeld.db "SELECT name FROM sqlite_master WHERE type='table' AND name='keygen_sessions';" 2>/dev/null | grep -q "keygen_sessions"; then
        log_info "Waiting for migrations to complete... (attempt $retry_count/$max_retries)"
        continue
    fi

    # Check all enclaves are healthy via API
    all_initialized=true
    for enclave_id in {0..2}; do
        if ! check_enclave_initialized $enclave_id 2>/dev/null; then
            all_initialized=false
            break
        fi
    done

    if $all_initialized; then
        all_enclaves_initialized=true
        break
    else
        log_info "Waiting for all enclaves to initialize... (attempt $retry_count/$max_retries)"
    fi
done

if ! $all_enclaves_initialized; then
    log_step_error "Enclaves failed to initialize within ${max_retries}s"
    exit 1
fi

log_step "All enclaves initialized and healthy"

test_passed "Test 1: Initial KMS Setup and Key Generation"

echo ""

# Test 2: Setup Bitcoin and perform a signing operation
echo "📋 Test 2: MuSig2 Signing Operation with KMS Keys"
echo "---------------------------------------------------"

log_info "Setting up Bitcoin regtest environment..."
if ! ./scripts/setup-regtest.sh >/tmp/keymeld_test_bitcoin_setup.log 2>&1; then
    log_step_error "Failed to setup Bitcoin regtest"
    cat /tmp/keymeld_test_bitcoin_setup.log
    exit 1
fi
log_step "Bitcoin regtest environment ready"

log_info "Running MuSig2 demo to test signing with KMS-backed keys..."
if [ -n "${SKIP_BUILD:-}" ] && [ -f "target/debug/keymeld_demo" ]; then
    DEMO_CMD="./target/debug/keymeld_demo"
else
    DEMO_CMD="cargo run --bin keymeld_demo --"
fi
if $DEMO_CMD plain \
    --config config/example-nix.yaml \
    --amount $TEST_AMOUNT \
    --destination $TEST_DEST >/tmp/keymeld_test_signing.log 2>&1; then
    log_step "Successfully completed MuSig2 signing with KMS keys"
    test_passed "Test 2: MuSig2 Signing Operation with KMS Keys"
else
    log_step_error "MuSig2 signing failed"
    cat /tmp/keymeld_test_signing.log
    test_failed "Test 2: MuSig2 Signing Operation with KMS Keys"
    exit 1
fi

echo ""

# Test 3: Restart enclaves and verify they come back healthy
echo "📋 Test 3: Enclave Restart and Recovery"
echo "----------------------------------------------"

log_info "Stopping all enclaves..."
pgrep -x keymeld-enclave 2>/dev/null | xargs -r kill 2>/dev/null || true
sleep 2

if pgrep -x keymeld-enclave >/dev/null 2>&1; then
    log_step_error "Failed to stop enclaves"
    exit 1
else
    log_step "All enclaves stopped"
fi

log_info "Restarting enclaves..."
ensure_vsock_proxies
for i in {0..2}; do
    port=$((5000 + i))
    cid=2
    RUST_LOG=info ENCLAVE_ID=${i} ENCLAVE_CID=${cid} VSOCK_PORT=${port} \
        LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
        AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-west-2 \
        ./target/debug/keymeld-enclave > logs/enclave-${i}.log 2>&1 &
done

# Wait for gateway to detect restarts (fast epoch detection runs every 5s)
# We need to wait long enough for multiple epoch detection cycles to ensure ALL enclaves are detected
log_info "Waiting for gateway to detect all enclave restarts..."
sleep 20

# Verify enclaves restarted and are healthy
all_enclaves_restarted=true
for enclave_id in {0..2}; do
    if ! check_enclave_initialized $enclave_id; then
        all_enclaves_restarted=false
    fi
done

if $all_enclaves_restarted; then
    log_step "All enclaves successfully restarted and healthy"
    test_passed "Test 3: Enclave Restart and Recovery"
else
    log_step_error "Some enclaves failed to restart correctly"
    test_failed "Test 3: Enclave Restart and Recovery"
    exit 1
fi

echo ""

# Test 4: Signing after restart
echo "📋 Test 4: MuSig2 Signing After Restart"
echo "----------------------------------------"

# Enclaves are up, but we need to ensure gateway has refreshed all public key caches
log_info "Waiting for gateway to refresh all enclave public key caches..."
sleep 3

log_info "Running MuSig2 demo after restart to verify keys still work..."
if $DEMO_CMD plain \
    --config config/example-nix.yaml \
    --amount $TEST_AMOUNT \
    --destination $TEST_DEST >/tmp/keymeld_test_signing_after_restart.log 2>&1; then
    log_step "Successfully completed MuSig2 signing after restart"
    test_passed "Test 4: MuSig2 Signing After Restart"
else
    log_step_error "MuSig2 signing failed after restart"
    cat /tmp/keymeld_test_signing_after_restart.log
    test_failed "Test 4: MuSig2 Signing After Restart"
    exit 1
fi

echo ""

# Test 5: Session Restoration After Restart (Using keymeld_session_test)
echo "📋 Test 5: Session Restoration + Full Signing After Restart"
echo "------------------------------------------------------------"

# This test uses the keymeld_session_test binary to:
# 1. Create keygen sessions (both plain and adaptor types) and fund them
# 2. Restart enclaves (triggers session restoration)
# 3. Create NEW signing sessions using the restored keygen sessions
# 4. Complete full MuSig2 signing and broadcast transactions
# This proves that restored sessions are fully functional, not just "accessible"

SESSION_DATA_FILE="/tmp/keymeld_session_test_data.json"

# Step 1: Create keygen sessions (plain and adaptor)
log_info "Creating keygen sessions for restoration test..."
if [ -n "${SKIP_BUILD:-}" ] && [ -f "target/debug/keymeld_session_test" ]; then
    SESSION_CMD="./target/debug/keymeld_session_test"
else
    SESSION_CMD="cargo run --bin keymeld_session_test --"
fi
if $SESSION_CMD keygen \
    --config config/example-nix.yaml \
    --output "$SESSION_DATA_FILE" \
    --amount $TEST_AMOUNT >/tmp/keymeld_session_keygen.log 2>&1; then
    log_step "Created keygen sessions (plain and adaptor)"
else
    log_step_error "Failed to create keygen sessions"
    cat /tmp/keymeld_session_keygen.log
    exit 1
fi

# Verify session data file was created
if [ -f "$SESSION_DATA_FILE" ]; then
    log_step "Session data saved to $SESSION_DATA_FILE"
    # Extract session IDs for logging (handle both compact and pretty-printed JSON)
    plain_session=$(grep -o '"plain_keygen_session_id"[[:space:]]*:[[:space:]]*"[^"]*"' "$SESSION_DATA_FILE" | grep -o '"[^"]*"$' | tr -d '"')
    adaptor_session=$(grep -o '"adaptor_keygen_session_id"[[:space:]]*:[[:space:]]*"[^"]*"' "$SESSION_DATA_FILE" | grep -o '"[^"]*"$' | tr -d '"')
    log_info "Plain session: $plain_session"
    log_info "Adaptor session: $adaptor_session"
else
    log_step_error "Session data file not created"
    exit 1
fi

# Count sessions before restart
sessions_before=$(sqlite3 data/keymeld.db \
    "SELECT COUNT(*) FROM keygen_sessions WHERE status LIKE '%Completed%';" 2>/dev/null || echo "0")
log_info "Completed keygen sessions before restart: $sessions_before"

# Step 2: Restart enclaves to trigger session restoration
log_info "Stopping all enclaves for session restoration test..."
pgrep -x keymeld-enclave 2>/dev/null | xargs -r kill 2>/dev/null || true
sleep 2

if pgrep -x keymeld-enclave >/dev/null 2>&1; then
    log_step_error "Failed to stop enclaves"
    exit 1
else
    log_step "All enclaves stopped"
fi

# Mark gateway log position to check for restoration messages
if [ -f "logs/gateway.log" ]; then
    gateway_log_lines_before=$(wc -l < logs/gateway.log)
else
    gateway_log_lines_before=0
fi

log_info "Restarting enclaves (sessions should be restored)..."
ensure_vsock_proxies
for i in {0..2}; do
    port=$((5000 + i))
    cid=2
    RUST_LOG=info ENCLAVE_ID=${i} ENCLAVE_CID=${cid} VSOCK_PORT=${port} \
        LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
        AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-west-2 \
        ./target/debug/keymeld-enclave > logs/enclave-${i}.log 2>&1 &
done

# Wait for gateway to detect restarts and restore sessions (epoch detection runs every 5s)
log_info "Waiting for gateway to detect all restarts and restore sessions..."
sleep 20

# Check that enclaves are healthy
all_healthy=true
for enclave_id in {0..2}; do
    if ! check_enclave_initialized $enclave_id; then
        all_healthy=false
    fi
done

if ! $all_healthy; then
    log_step_error "Enclaves failed to restart"
    exit 1
fi
log_step "All enclaves restarted"

# Check gateway logs for session restoration messages
restoration_logged=false
if [ -f "logs/gateway.log" ]; then
    new_log_content=$(tail -n +$((gateway_log_lines_before + 1)) logs/gateway.log 2>/dev/null || cat logs/gateway.log)
    if echo "$new_log_content" | grep -qi "Restoring sessions\|restored.*keygen\|keygen.*restored\|Restored sessions"; then
        restoration_logged=true
    fi
fi

if $restoration_logged; then
    log_step "Session restoration messages found in gateway logs"
else
    log_info "No explicit restoration messages (checking session accessibility instead)"
fi

# Step 3: Create NEW signing sessions and complete full MuSig2 signing
log_info "Creating signing sessions with restored keygen and completing full signing..."
log_info "This will create PSBTs, get approvals, complete MuSig2 signing, and broadcast transactions"
if $SESSION_CMD sign \
    --config config/example-nix.yaml \
    --input "$SESSION_DATA_FILE" >/tmp/keymeld_session_sign.log 2>&1; then
    log_step "Full signing completed with restored sessions"
    # Extract and display the broadcast transaction IDs (use || true to avoid failing on no match)
    plain_txid=$(grep -o "PLAIN.*Transaction broadcast successfully: [a-f0-9]*" /tmp/keymeld_session_sign.log 2>/dev/null | grep -o "[a-f0-9]\{64\}" | head -1 || true)
    adaptor_txid=$(grep -o "ADAPTOR.*Transaction broadcast successfully: [a-f0-9]*" /tmp/keymeld_session_sign.log 2>/dev/null | grep -o "[a-f0-9]\{64\}" | head -1 || true)
    if [ -n "$plain_txid" ]; then
        log_step "Plain session tx broadcast: $plain_txid"
    fi
    if [ -n "$adaptor_txid" ]; then
        log_step "Adaptor session tx broadcast: $adaptor_txid"
    fi
else
    log_step_error "Signing with restored sessions FAILED"
    cat /tmp/keymeld_session_sign.log
    exit 1
fi

# Cleanup session data file
rm -f "$SESSION_DATA_FILE"

test_passed "Test 5: Session Restoration + Full Signing After Restart"

echo ""

# Test 6: Check database integrity
echo "📋 Test 6: Database Integrity Checks"
echo "------------------------------------"

log_info "Verifying database schema and session data..."

test6_passed=true

# Check that keygen sessions were created
keygen_count=$(sqlite3 data/keymeld.db "SELECT COUNT(*) FROM keygen_sessions;" 2>/dev/null || echo "0")
if [ "$keygen_count" -gt 0 ]; then
    log_step "Found $keygen_count keygen session(s) in database"
else
    log_step_error "No keygen sessions found in database"
    test6_passed=false
fi

# Check that signing sessions were created
signing_count=$(sqlite3 data/keymeld.db "SELECT COUNT(*) FROM signing_sessions;" 2>/dev/null || echo "0")
if [ "$signing_count" -gt 0 ]; then
    log_step "Found $signing_count signing session(s) in database"
else
    log_step_error "No signing sessions found in database"
    test6_passed=false
fi

# Check that participants were registered
participant_count=$(sqlite3 data/keymeld.db "SELECT COUNT(*) FROM keygen_participants;" 2>/dev/null || echo "0")
if [ "$participant_count" -gt 0 ]; then
    log_step "Found $participant_count participant record(s) in database"
else
    log_step_error "No participant records found in database"
    test6_passed=false
fi

# Check completed sessions
completed_keygen=$(sqlite3 data/keymeld.db "SELECT COUNT(*) FROM keygen_sessions WHERE status LIKE '%Completed%';" 2>/dev/null || echo "0")
if [ "$completed_keygen" -gt 0 ]; then
    log_step "Found $completed_keygen completed keygen session(s)"
else
    log_step_error "No completed keygen sessions found"
    test6_passed=false
fi

if $test6_passed; then
    test_passed "Test 6: Database Integrity Checks"
else
    test_failed "Test 6: Database Integrity Checks"
fi

echo ""

# Test Summary
echo "📊 Test Summary"
echo "==============="
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
echo ""

# Cleanup temp files
rm -f /tmp/keymeld_test_epoch_*.txt
rm -f /tmp/keymeld_test_signing*.log

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ All KMS E2E tests passed!${NC}"
    exit 0
else
    echo -e "${RED}❌ Some KMS E2E tests failed${NC}"
    exit 1
fi
