#!/usr/bin/env bash
# Clean all KeyMeld data and stop services
set -euo pipefail

echo "🧹 Cleaning all data..."
echo "🛑 Stopping services..."
# Kill keymeld processes - use pgrep to find PIDs then kill individually
# This avoids pkill -f which can match parent shell command lines
for proc in keymeld-gateway keymeld-enclave keymeld_demo keymeld_session_test; do
    # Find actual binary processes (not shell scripts containing the name)
    pgrep -x "$proc" 2>/dev/null | xargs -r kill 2>/dev/null || true
done
pkill -x moto_server || true
vsock-proxy stop >/dev/null 2>&1 || true

# Stop bitcoind gracefully and wait for it to fully stop
if pgrep -x bitcoind >/dev/null 2>&1; then
    # Try graceful shutdown first via RPC
    bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 stop 2>/dev/null || true
    # Wait up to 5 seconds for graceful shutdown
    for i in {1..10}; do
        if ! pgrep -x bitcoind >/dev/null 2>&1; then
            break
        fi
        sleep 0.5
    done
    # Force kill if still running
    pkill -9 -x bitcoind 2>/dev/null || true
    sleep 1
fi
echo "✅ All services stopped"
rm -rf data logs result
# Only clean binaries if not using pre-built (CI sets SKIP_BUILD)
if [ -z "${SKIP_BUILD:-}" ]; then
    rm -rf target/debug/keymeld-* target/debug/keymeld_*
fi
mkdir -p data logs
echo "✅ Clean complete"
