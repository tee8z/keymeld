#!/bin/bash
set -e

BLOCKS=${1:-10}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "Mining $BLOCKS blocks in regtest..."

if ! docker compose ps bitcoin | grep -q "Up"; then
    echo "Error: Bitcoin service is not running. Start it with: docker compose up bitcoin"
    exit 1
fi

echo "Ensuring mining wallet exists..."
docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 createwallet mining_wallet >/dev/null 2>&1 || true

MINING_ADDRESS=$(docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 getnewaddress | tr -d '\r\n')

if [ -z "$MINING_ADDRESS" ]; then
    echo "Error: Could not get mining address"
    exit 1
fi

echo "Mining to address: $MINING_ADDRESS"

docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 generatetoaddress $BLOCKS $MINING_ADDRESS

BLOCK_HEIGHT=$(docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 getblockcount | tr -d '\r\n')
BALANCE=$(docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 getbalance | tr -d '\r\n')

echo "✅ Successfully mined $BLOCKS blocks"
echo "📊 Current block height: $BLOCK_HEIGHT"
echo "💰 Wallet balance: $BALANCE BTC"
echo ""
echo "💡 Tip: You can now fund addresses using: ./scripts/fund-address.sh <address> <amount>"
