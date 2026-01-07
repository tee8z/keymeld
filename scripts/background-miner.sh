#!/usr/bin/env bash
# Background block miner for regtest
# Generates blocks at a regular interval to confirm transactions
# Usage: ./background-miner.sh [interval_seconds] [blocks_per_interval]
#
# Examples:
#   ./background-miner.sh           # Default: 1 block every 0.5 seconds
#   ./background-miner.sh 1 1       # 1 block every 1 second
#   ./background-miner.sh 0.25 1    # 1 block every 0.25 seconds (fast mode)
#
# The script writes its PID to /tmp/keymeld-background-miner.pid
# To stop: kill $(cat /tmp/keymeld-background-miner.pid)

set -euo pipefail

INTERVAL="${1:-0.5}"
BLOCKS="${2:-1}"
PID_FILE="/tmp/keymeld-background-miner.pid"

# Bitcoin RPC settings
RPC_USER="${BITCOIN_RPC_USER:-keymeld}"
RPC_PASS="${BITCOIN_RPC_PASS:-keymeldpass123}"
RPC_WALLET="${BITCOIN_RPC_WALLET:-keymeld_coordinator}"

# Check if already running
if [[ -f "$PID_FILE" ]]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "Background miner already running (PID: $OLD_PID)"
        echo "To stop: kill $OLD_PID"
        exit 0
    else
        rm -f "$PID_FILE"
    fi
fi

# Get mining address
MINER_ADDR=$(bitcoin-cli -regtest -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" \
    -rpcwallet="$RPC_WALLET" getnewaddress 2>/dev/null) || {
    echo "❌ Failed to get mining address. Is bitcoind running with wallet '$RPC_WALLET' loaded?"
    exit 1
}

echo "⛏️  Background block miner starting..."
echo "   Interval: ${INTERVAL}s"
echo "   Blocks per interval: $BLOCKS"
echo "   Mining to: $MINER_ADDR"
echo "   PID file: $PID_FILE"

# Write PID file
echo $$ > "$PID_FILE"

# Cleanup on exit
cleanup() {
    rm -f "$PID_FILE"
    echo "⛏️  Background miner stopped"
}
trap cleanup EXIT

BLOCKS_MINED=0
START_TIME=$(date +%s)

while true; do
    if bitcoin-cli -regtest -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" \
        generatetoaddress "$BLOCKS" "$MINER_ADDR" > /dev/null 2>&1; then
        BLOCKS_MINED=$((BLOCKS_MINED + BLOCKS))
    fi
    sleep "$INTERVAL"
done
