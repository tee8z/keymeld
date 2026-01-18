#!/usr/bin/env bash
set -euo pipefail

MODE="$1"
COUNT="$2"
AMOUNT="$3"

# Use HAProxy port if set (for high concurrency tests), otherwise direct bitcoind
BITCOIN_RPC_PORT="${BITCOIN_RPC_PORT:-18443}"
echo "📡 Using Bitcoin RPC port: $BITCOIN_RPC_PORT"

# Clean up any old demo processes (but NOT gateway/enclaves - they're managed by justfile)
pkill -9 -f keymeld_demo 2>/dev/null || true

# Use dedicated funding script for faster wallet setup
# Parallelism of 10 provides good speedup without overwhelming Bitcoin Core RPC
./scripts/fund-wallets.sh "$COUNT" 0.00055 50 10

echo ""
DEMO_BIN="$(pwd)/target/debug/keymeld_demo"
if [ -n "${SKIP_BUILD:-}" ] && [ -f "$DEMO_BIN" ]; then
    echo "✅ Using pre-built binary"
else
    echo "🔨 Building binary..."
    cargo build --bin keymeld_demo >/dev/null 2>&1
    echo "✅ Binary ready"
fi

# Export CMAKE_LIBRARY_PATH so subshells can find libraries
export LD_LIBRARY_PATH="${CMAKE_LIBRARY_PATH:-}"

echo ""
echo "🧹 Cleaning up old test artifacts..."
rm -f /tmp/keymeld-stress-test/exit-*.code
rm -rf logs/stress-test
mkdir -p logs/stress-test

# Start background block miner to avoid RPC contention
# Each test needs blocks mined for funding confirmations, but having each test
# call generate_to_address independently causes contention with many parallel tests.
./scripts/background-miner.sh 0.5 1 &
MINER_PID=$!
sleep 0.5  # Give miner time to start

# Cleanup function to stop miner on exit
cleanup() {
    if kill -0 $MINER_PID 2>/dev/null; then
        kill $MINER_PID 2>/dev/null || true
        wait $MINER_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "🚀 Launching $COUNT parallel tests..."
declare -a PIDS
START=$(date +%s)

# Calculate jitter parameters for staggered starts
# For 1000 instances, spread over ~10 seconds (10ms average delay per instance)
JITTER_MAX_MS=20  # Max random delay in milliseconds per instance

for i in $(seq 0 $((COUNT - 1))); do
    cfg="/tmp/keymeld-stress-test/config-$i.yaml"
    keys="/tmp/keymeld-stress-test/keys-$i"
    log="logs/stress-test/test-$i.log"
    mkdir -p "$keys"

    # Create config file (using BITCOIN_RPC_PORT which may be HAProxy or direct)
    # Enable RPC batcher for high-concurrency tests (100+)
    cat > "$cfg" <<EOF
network: regtest
num_signers: 3
gateway_url: "http://127.0.0.1:8090"
bitcoin_rpc_url: "http://127.0.0.1:${BITCOIN_RPC_PORT}"
bitcoin_rpc_auth:
  username: "keymeld"
  password: "keymeldpass123"
key_files_dir: "$keys"
use_rpc_batcher: ${USE_RPC_BATCHER:-false}
rpc_queue_dir: "/tmp/keymeld-rpc-queue"
EOF

    # Add random jitter to stagger instance starts and avoid thundering herd
    JITTER_MS=$((RANDOM % JITTER_MAX_MS))
    sleep "0.0${JITTER_MS}"

    ("$DEMO_BIN" "$MODE" --config "$cfg" --amount "$AMOUNT" \
        < /dev/null > "$log" 2>&1
     echo $? > "/tmp/keymeld-stress-test/exit-$i.code") &
    PIDS[$i]=$!

    # Progress update every 100 instances
    if (( (i + 1) % 100 == 0 )); then
        echo "   Launched $((i + 1))/$COUNT instances..."
    fi
done
echo "   All $COUNT instances launched"

echo ""
echo "⏳ Waiting for completion..."
echo ""

# Monitor progress while tests run
COMPLETED=0
LAST_UPDATE=0  # Start at 0 to force immediate first update

while true; do
    RUNNING=0
    COMPLETED_NOW=0
    CURRENT_TIME=$(date +%s)

    for i in $(seq 0 $((COUNT - 1))); do
        if [[ -f "/tmp/keymeld-stress-test/exit-$i.code" ]]; then
            COMPLETED_NOW=$((COMPLETED_NOW + 1))
        elif kill -0 ${PIDS[$i]} 2>/dev/null; then
            RUNNING=$((RUNNING + 1))
        else
            # Process finished but exit code file might not exist yet
            # Wait a moment and check again
            sleep 0.1
            if [[ -f "/tmp/keymeld-stress-test/exit-$i.code" ]]; then
                COMPLETED_NOW=$((COMPLETED_NOW + 1))
            else
                # Process died without writing exit code - treat as failure
                echo "1" > "/tmp/keymeld-stress-test/exit-$i.code"
                COMPLETED_NOW=$((COMPLETED_NOW + 1))
            fi
        fi
    done

    # Check if all tests completed
    if [[ $COMPLETED_NOW -eq $COUNT ]]; then
        echo "   Progress: $COMPLETED_NOW/$COUNT completed, $RUNNING running"
        break
    fi

    # Show status every 3 seconds or when tests complete/start
    TIME_SINCE_UPDATE=$((CURRENT_TIME - LAST_UPDATE))
    if [[ $COMPLETED_NOW -ne $COMPLETED ]] || [[ $TIME_SINCE_UPDATE -ge 3 ]]; then
        COMPLETED=$COMPLETED_NOW
        LAST_UPDATE=$CURRENT_TIME

        echo "   Progress: $COMPLETED/$COUNT completed, $RUNNING running"

        # Show current status of each running test
        for i in $(seq 0 $((COUNT - 1))); do
            if kill -0 ${PIDS[$i]} 2>/dev/null && [[ ! -f "/tmp/keymeld-stress-test/exit-$i.code" ]]; then
                log="logs/stress-test/test-$i.log"
                if [[ -f "$log" ]]; then
                    STATUS=$(tail -50 "$log" 2>/dev/null | \
                        grep -E "Phase|Starting|Funding|complete|waiting|collecting|Keygen|Signing|broadcast|approved" 2>/dev/null | \
                        tail -1 | \
                        sed 's/^[0-9T:.Z-]* *[A-Z]* *//' | \
                        sed 's/.*keymeld[_a-z]*:://' | \
                        sed 's/.*keymeld_[a-z]*:://' || true)

                    if [[ -n "$STATUS" ]]; then
                        echo "      Test $i: $STATUS"
                    else
                        echo "      Test $i: Running..."
                    fi
                else
                    echo "      Test $i: Starting..."
                fi
            fi
        done
        echo ""
    fi

    sleep 1
done

echo ""
echo "📊 Results:"
SUCCESS=0
FAIL=0
for i in $(seq 0 $((COUNT - 1))); do
    code=$(cat "/tmp/keymeld-stress-test/exit-$i.code" 2>/dev/null || echo 1)
    txid=$(grep "Transaction broadcast successfully:" "logs/stress-test/test-$i.log" 2>/dev/null | tail -1 | sed 's/.*: //' || echo "")

    if [[ "$code" == "0" ]] && [[ -n "$txid" ]]; then
        echo "   ✅ Test $i: SUCCESS (tx: $txid)"
        SUCCESS=$((SUCCESS + 1))
    else
        if [[ "$code" != "0" ]]; then
            echo "   ❌ Test $i: FAILED (exit code: $code, log: logs/stress-test/test-$i.log)"
        elif [[ -z "$txid" ]]; then
            # Show last log line to see where it got stuck
            last_line=$(tail -1 "logs/stress-test/test-$i.log" 2>/dev/null | sed 's/^[0-9T:.Z-]* *[A-Z]* *//' | sed 's/.*keymeld[_a-z]*:://' | sed 's/.*keymeld_[a-z]*:://' || echo "no logs")
            echo "   ❌ Test $i: FAILED (no transaction broadcast, last: $last_line)"
        else
            echo "   ❌ Test $i: FAILED (unknown reason, log: logs/stress-test/test-$i.log)"
        fi
        FAIL=$((FAIL + 1))
    fi
done

DURATION=$(($(date +%s) - START))
echo ""
echo "📊 Summary: $SUCCESS passed, $FAIL failed (${DURATION}s)"
[[ $FAIL -eq 0 ]] && echo "🎉 All tests passed!" || exit 1
