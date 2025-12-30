#!/usr/bin/env bash
set -euo pipefail

MODE="$1"
COUNT="$2"
AMOUNT="$3"

# Clean up any old demo processes (but NOT gateway/enclaves - they're managed by justfile)
pkill -9 -f keymeld_demo 2>/dev/null || true

# Fund Bitcoin wallets
echo "📊 Funding Bitcoin wallets..."
bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
    createwallet 'keymeld_coordinator' >/dev/null 2>&1 || true
bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
    loadwallet 'keymeld_coordinator' >/dev/null 2>&1 || true

for i in $(seq 0 $((COUNT - 1))); do
    wallet="stress_test_$i"
    bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        createwallet "$wallet" >/dev/null 2>&1 || true
    bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        loadwallet "$wallet" >/dev/null 2>&1 || true
    addr=$(bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        -rpcwallet=$wallet getnewaddress)
    bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        -rpcwallet=keymeld_coordinator sendtoaddress $addr 0.00055 > /dev/null
    echo "   ✓ Wallet $i funded"
done

addr=$(bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
    -rpcwallet=keymeld_coordinator getnewaddress)
bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
    generatetoaddress 6 $addr > /dev/null
echo "   ✓ Blocks mined"

for i in $(seq 0 $((COUNT - 1))); do
    bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        unloadwallet "stress_test_$i" >/dev/null 2>&1 || true
done

echo ""
echo "🔨 Building binary..."
cargo build --bin keymeld_demo >/dev/null 2>&1
DEMO_BIN="$(pwd)/target/debug/keymeld_demo"
echo "✅ Binary ready"

# Export CMAKE_LIBRARY_PATH so subshells can find libraries
export LD_LIBRARY_PATH="${CMAKE_LIBRARY_PATH:-}"

echo ""
echo "🚀 Launching $COUNT parallel tests..."
mkdir -p logs/stress-test
declare -a PIDS
START=$(date +%s)

for i in $(seq 0 $((COUNT - 1))); do
    cfg="/tmp/keymeld-stress-test/config-$i.yaml"
    keys="/tmp/keymeld-stress-test/keys-$i"
    log="logs/stress-test/test-$i.log"
    mkdir -p "$keys"

    # Create config file
    cat > "$cfg" <<EOF
network: regtest
num_signers: 3
gateway_url: "http://127.0.0.1:8080"
bitcoin_rpc_url: "http://127.0.0.1:18443"
bitcoin_rpc_auth:
  username: "keymeld"
  password: "keymeldpass123"
key_files_dir: "$keys"
EOF

    echo "   Launching test $i..."
    ("$DEMO_BIN" "$MODE" --config "$cfg" --amount "$AMOUNT" \
        < /dev/null > "$log" 2>&1
     echo $? > "/tmp/keymeld-stress-test/exit-$i.code") &
    PIDS[$i]=$!
done

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
    if [[ "$code" == "0" ]]; then
        txid=$(grep "Transaction broadcast successfully:" "logs/stress-test/test-$i.log" 2>/dev/null | tail -1 | sed 's/.*: //' || echo "")
        if [[ -n "$txid" ]]; then
            echo "   ✅ Test $i: SUCCESS (tx: $txid)"
        else
            echo "   ✅ Test $i: SUCCESS"
        fi
        SUCCESS=$((SUCCESS + 1))
    else
        echo "   ❌ Test $i: FAILED (code: $code, log: logs/stress-test/test-$i.log)"
        FAIL=$((FAIL + 1))
    fi
done

DURATION=$(($(date +%s) - START))
echo ""
echo "📊 Summary: $SUCCESS passed, $FAIL failed (${DURATION}s)"
[[ $FAIL -eq 0 ]] && echo "🎉 All tests passed!" || exit 1
