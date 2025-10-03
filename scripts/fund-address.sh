#!/bin/bash
set -e

ADDRESS=${1}
AMOUNT=${2:-1}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

if [ -z "$ADDRESS" ]; then
    echo "Usage: $0 <address> [amount]"
    echo ""
    echo "Examples:"
    echo "  $0 bcrt1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh 1.5"
    echo "  $0 bcrt1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh     # sends 1 BTC"
    exit 1
fi

if ! [[ $AMOUNT =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "Error: Amount must be a valid number (e.g., 1, 0.5, 10.25)"
    exit 1
fi

echo "Funding address $ADDRESS with $AMOUNT BTC..."

if ! docker compose ps bitcoin | grep -q "Up"; then
    echo "Error: Bitcoin service is not running. Start it with: docker compose up bitcoin"
    exit 1
fi

echo "Ensuring mining wallet exists..."
docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 createwallet mining_wallet >/dev/null 2>&1 || true

BALANCE=$(docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 getbalance | tr -d '\r\n')

echo "Current wallet balance: $BALANCE BTC"

if (( $(echo "$BALANCE < $AMOUNT" | bc -l) )); then
    echo "⚠️  Insufficient funds! Mining some blocks first..."

    BLOCKS_NEEDED=$(echo "($AMOUNT / 50) + 1" | bc -l | cut -d. -f1)
    if [ "$BLOCKS_NEEDED" -lt "101" ]; then
        BLOCKS_NEEDED=101
    fi

    echo "Mining $BLOCKS_NEEDED blocks to ensure sufficient mature funds..."
    MINING_ADDRESS=$(docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 getnewaddress | tr -d '\r\n')
    docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 generatetoaddress $BLOCKS_NEEDED $MINING_ADDRESS >/dev/null

    NEW_BALANCE=$(docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 getbalance | tr -d '\r\n')
    echo "New wallet balance after mining: $NEW_BALANCE BTC"
fi

echo "Sending $AMOUNT BTC to $ADDRESS..."
TXID=$(docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 sendtoaddress $ADDRESS $AMOUNT | tr -d '\r\n')

if [ -z "$TXID" ]; then
    echo "❌ Error: Failed to send transaction"
    exit 1
fi

echo "✅ Transaction sent successfully!"
echo "📝 Transaction ID: $TXID"

echo "Mining 1 block to confirm transaction..."
MINING_ADDRESS=$(docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 getnewaddress | tr -d '\r\n')
docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 generatetoaddress 1 $MINING_ADDRESS >/dev/null

CONFIRMATIONS=$(docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 gettransaction $TXID | grep -o '"confirmations": [0-9]*' | cut -d: -f2 | tr -d ' ')

echo "🎉 Transaction confirmed with $CONFIRMATIONS confirmations!"

FINAL_BALANCE=$(docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 getbalance | tr -d '\r\n')
echo "💰 Remaining wallet balance: $FINAL_BALANCE BTC"

echo ""
echo "💡 You can verify the transaction in Esplora at:"
echo "   http://localhost:3002/api/tx/$TXID"
