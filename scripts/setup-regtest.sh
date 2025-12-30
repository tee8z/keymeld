#!/usr/bin/env bash
# Setup Bitcoin regtest environment
set -euo pipefail

echo "🏦 Setting up Bitcoin regtest environment..."
mkdir -p data/bitcoin logs

if ! pgrep -f bitcoind > /dev/null; then
    echo "Starting Bitcoin Core..."
    bitcoind -regtest -daemon -datadir=./data/bitcoin \
        -rpcuser=keymeld -rpcpassword=keymeldpass123 -rpcport=18443 \
        -port=18444 -fallbackfee=0.0001 -mintxfee=0.00001
    echo "Waiting for Bitcoin Core to start..."
    for i in {1..30}; do
        if bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 getblockchaininfo >/dev/null 2>&1; then
            echo "Bitcoin Core RPC ready"
            break
        fi
        sleep 1
    done
fi

bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 createwallet "keymeld_coordinator" >/dev/null 2>&1 || true
bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 loadwallet "keymeld_coordinator" >/dev/null 2>&1 || true
echo "Generating initial blocks..."
addr=$(bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 -rpcwallet=keymeld_coordinator getnewaddress)
bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 generatetoaddress 101 $addr > /dev/null
echo "✅ Bitcoin regtest ready with funded coordinator wallet"
