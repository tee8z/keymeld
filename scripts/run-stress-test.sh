#!/usr/bin/env bash
# KeyMeld Stress Test Runner
# This script handles the full stress test workflow including setup, service management, and test execution
set -euo pipefail

MODE="$1"
COUNT="$2"
AMOUNT="${3:-50000}"

if [[ "$MODE" != "plain" && "$MODE" != "adaptor" ]]; then
    echo "❌ Error: mode must be 'plain' or 'adaptor'"
    exit 1
fi

echo "🔥 KeyMeld Stress Test"
echo "======================"
echo "Mode: $MODE"
echo "Parallel instances: $COUNT"
echo "Amount per tx: $AMOUNT sats"
echo ""

# Partial clean (preserve bitcoin data)
echo "🧹 Cleaning database and logs..."
rm -rf data/keymeld.db* logs/stress-test
mkdir -p /tmp/keymeld-stress-test
pkill -9 -f keymeld-gateway 2>/dev/null || true
pkill -9 -f keymeld-enclave 2>/dev/null || true
pkill -9 -f keymeld_demo 2>/dev/null || true
sleep 1

echo "🚀 Starting VSock proxy..."
vsock-proxy start > /dev/null 2>&1
sleep 1

echo "🏦 Setting up Bitcoin regtest..."
./scripts/setup-regtest.sh > /dev/null 2>&1

echo "🔨 Building project..."
cargo build > /dev/null 2>&1

echo "🚀 Starting services..."
./scripts/start-services.sh > /dev/null 2>&1
sleep 3

# Wait for gateway to be ready
echo "⏳ Waiting for gateway to be ready..."
for i in {1..30}; do
    # Check if gateway process is running and try a simple connection
    if pgrep -f keymeld-gateway >/dev/null && nc -z localhost 8080 2>/dev/null; then
        echo "✅ Services ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ Gateway failed to start after 30 seconds"
        echo "Gateway process status:"
        pgrep -f keymeld-gateway || echo "No gateway process found"
        echo "Port 8080 status:"
        netstat -tlnp | grep :8080 || echo "Nothing listening on port 8080"
        if [ -f logs/gateway.log ]; then
            echo "Gateway logs:"
            tail -20 logs/gateway.log
        fi
        exit 1
    fi
    sleep 1
done
echo ""

echo "🧪 Running stress test..."
bash scripts/stress-test.sh "$MODE" "$COUNT" "$AMOUNT"
