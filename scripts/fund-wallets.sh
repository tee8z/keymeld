#!/usr/bin/env bash
set -euo pipefail

# fund-wallets.sh - Optimized Bitcoin wallet funding for stress tests
# Usage: ./scripts/fund-wallets.sh <count> [amount] [batch_size] [creation_parallelism]
#
# Arguments:
#   count                - Number of wallets to create and fund
#   amount               - Amount to fund each wallet with (default: 0.00055 BTC)
#   batch_size           - Number of wallets to fund per batch (default: 50)
#   creation_parallelism - Max parallel wallet creations (default: 10)
#
# Environment:
#   BITCOIN_RPC_PORT     - RPC port to use (default: 18443, use 18550 for HAProxy)

COUNT="$1"
AMOUNT="${2:-0.00055}"
BATCH_SIZE="${3:-50}"

# Use HAProxy port if set, otherwise direct bitcoind
BITCOIN_RPC_PORT="${BITCOIN_RPC_PORT:-18443}"

# Build common bitcoin-cli args
BTC_CLI="bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 -rpcport=$BITCOIN_RPC_PORT"

echo "📊 Funding $COUNT Bitcoin wallets with $AMOUNT BTC each..."
echo "   Using Bitcoin RPC port: $BITCOIN_RPC_PORT"

# Ensure coordinator wallet exists
$BTC_CLI createwallet 'keymeld_coordinator' >/dev/null 2>&1 || true
$BTC_CLI loadwallet 'keymeld_coordinator' >/dev/null 2>&1 || true

# Check coordinator wallet balance
balance=$($BTC_CLI -rpcwallet=keymeld_coordinator getbalance 2>/dev/null || echo "0")
required=$(echo "$COUNT * $AMOUNT + 0.1" | bc -l)

if (( $(echo "$balance < $required" | bc -l) )); then
    echo "   ⚠️  Coordinator wallet balance ($balance BTC) insufficient for funding."
    echo "   ⚠️  Required: $required BTC. Generating initial funds..."

    # Check current block height to determine if halvings have depleted block rewards
    # Regtest halves every 150 blocks, so after ~3000 blocks the reward is negligible
    block_height=$($BTC_CLI getblockcount 2>/dev/null || echo "0")
    halvings=$((block_height / 150))

    if [[ $halvings -ge 20 ]]; then
        echo "   ❌ ERROR: Block reward has halved $halvings times (height: $block_height)"
        echo "   ❌ Current block reward is too small to fund wallets."
        echo "   ❌ Please run 'just clean' to reset the regtest chain, then retry."
        exit 1
    fi

    # Generate some coins for the coordinator
    # Need 101 blocks for first coinbase to mature (100 confirmations required)
    addr=$($BTC_CLI -rpcwallet=keymeld_coordinator getnewaddress)
    $BTC_CLI generatetoaddress 101 $addr >/dev/null

    # Wait for wallet to update balance (can take a moment after block generation)
    sleep 1

    # Verify balance is now sufficient
    new_balance=$($BTC_CLI -rpcwallet=keymeld_coordinator getbalance 2>/dev/null || echo "0")
    if (( $(echo "$new_balance < $required" | bc -l) )); then
        echo "   ⚠️  Balance still insufficient ($new_balance BTC), generating more blocks..."
        $BTC_CLI generatetoaddress 50 $addr >/dev/null
        sleep 1
        new_balance=$($BTC_CLI -rpcwallet=keymeld_coordinator getbalance 2>/dev/null || echo "0")
    fi

    # Final check - if still not enough, the chain needs reset
    if (( $(echo "$new_balance < $required" | bc -l) )); then
        echo "   ❌ ERROR: Could not generate sufficient funds ($new_balance BTC < $required BTC)"
        echo "   ❌ Block rewards may be depleted. Run 'just clean' to reset the regtest chain."
        exit 1
    fi

    echo "   ✓ Generated initial funds for coordinator wallet (balance: $new_balance BTC)"
fi

CREATION_PARALLELISM="${4:-10}"

echo "   Creating $COUNT wallets with parallelism of $CREATION_PARALLELISM..."
start_time=$(date +%s.%3N)

declare -a WALLET_ADDRS

# Function to create a single wallet
# Uses BITCOIN_RPC_PORT from environment (exported below)
create_wallet() {
    local i=$1
    local wallet="stress_test_$i"
    local addr=""
    local btc_cli="bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 -rpcport=${BITCOIN_RPC_PORT:-18443}"

    # Unload first in case it exists
    $btc_cli unloadwallet "$wallet" >/dev/null 2>&1 || true

    # Create wallet (ignore error if already exists)
    $btc_cli createwallet "$wallet" >/dev/null 2>&1 || true

    # Load wallet with retry logic
    local loaded=false
    for retry in 1 2 3 4 5; do
        if $btc_cli loadwallet "$wallet" >/dev/null 2>&1; then
            loaded=true
            break
        fi
        # Wallet might already be loaded, which is fine
        if $btc_cli -rpcwallet="$wallet" getwalletinfo >/dev/null 2>&1; then
            loaded=true
            break
        fi
        sleep 0.2
    done

    if [[ "$loaded" != "true" ]]; then
        echo "ERROR: Failed to load wallet $wallet" >&2
        return 1
    fi

    # Get address with retry logic - must succeed
    for retry in 1 2 3 4 5; do
        addr=$($btc_cli -rpcwallet="$wallet" getnewaddress 2>/dev/null) && break
        sleep 0.2
    done

    # Immediately unload wallet to free up slot for other parallel workers
    $btc_cli unloadwallet "$wallet" >/dev/null 2>&1 || true

    if [[ -z "$addr" ]]; then
        echo "ERROR: Failed to get address for wallet $wallet" >&2
        return 1
    fi

    echo "$addr" > "/tmp/keymeld-wallet-addr-$i"
}

export -f create_wallet
export BITCOIN_RPC_PORT

# Create wallets in parallel batches
# Using xargs for controlled parallelism - safer than unlimited background jobs
# Track progress with a counter file
PROGRESS_FILE="/tmp/keymeld-wallet-progress"
echo "0" > "$PROGRESS_FILE"
export PROGRESS_FILE

# Wrapper function to track progress
create_wallet_with_progress() {
    create_wallet "$1"
    # Atomically increment and report progress
    flock "$PROGRESS_FILE" bash -c '
        count=$(<"'"$PROGRESS_FILE"'")
        count=$((count + 1))
        echo "$count" > "'"$PROGRESS_FILE"'"
        total='"$COUNT"'
        if (( count % 50 == 0 )) || (( count == total )); then
            pct=$((count * 100 / total))
            printf "\r   Creating wallets: %d/%d (%d%%)..." "$count" "$total" "$pct" >&2
        fi
    '
}
export -f create_wallet_with_progress
export COUNT

seq 0 $((COUNT - 1)) | xargs -P "$CREATION_PARALLELISM" -I {} bash -c 'create_wallet_with_progress "$@"' _ {}
echo ""  # newline after progress
rm -f "$PROGRESS_FILE"

# Verify all address files were created
missing=0
for i in $(seq 0 $((COUNT - 1))); do
    if [[ ! -f "/tmp/keymeld-wallet-addr-$i" ]]; then
        echo "   ⚠️  Missing address file for wallet $i" >&2
        missing=$((missing + 1))
    fi
done

if [[ $missing -gt 0 ]]; then
    echo "   ❌ Failed to create $missing wallets" >&2
    exit 1
fi

echo "   ✓ Created $COUNT wallets..."

creation_time=$(date +%s.%3N)
creation_duration=$(echo "scale=2; $creation_time - $start_time" | bc)
echo "   ✓ Created $COUNT wallets in ${creation_duration}s"

# Collect addresses
for i in $(seq 0 $((COUNT - 1))); do
    WALLET_ADDRS[$i]=$(cat "/tmp/keymeld-wallet-addr-$i")
    rm -f "/tmp/keymeld-wallet-addr-$i"
done

# Fund wallets in optimized batches
BATCH_COUNT=$(((COUNT + BATCH_SIZE - 1) / BATCH_SIZE))
echo "   Funding in $BATCH_COUNT batches of up to $BATCH_SIZE wallets..."

funding_start_time=$(date +%s.%3N)

for batch_num in $(seq 0 $((BATCH_COUNT - 1))); do
    batch_start=$((batch_num * BATCH_SIZE))
    batch_end=$((batch_start + BATCH_SIZE - 1))
    if [[ $batch_end -gt $((COUNT - 1)) ]]; then
        batch_end=$((COUNT - 1))
    fi

    batch_size=$((batch_end - batch_start + 1))
    batch_start_time=$(date +%s.%3N)

    # Build sendmany command for bulk funding
    sendmany_json="{"
    for i in $(seq $batch_start $batch_end); do
        addr="${WALLET_ADDRS[$i]}"
        sendmany_json="${sendmany_json}\"$addr\": $AMOUNT"
        if [[ $i -lt $batch_end ]]; then
            sendmany_json="${sendmany_json},"
        fi
    done
    sendmany_json="${sendmany_json}}"

    # Send bulk transaction
    txid=$($BTC_CLI -rpcwallet=keymeld_coordinator sendmany "" "$sendmany_json")

    batch_fund_time=$(date +%s.%3N)
    fund_duration=$(echo "scale=2; $batch_fund_time - $batch_start_time" | bc)

    echo "   ✓ Batch $((batch_num + 1))/$BATCH_COUNT: Funded $batch_size wallets in ${fund_duration}s (tx: ${txid:0:16}...)"

    # Confirm this batch before funding the next (except for the last batch)
    if [[ $batch_num -lt $((BATCH_COUNT - 1)) ]]; then
        confirm_start_time=$(date +%s.%3N)
        addr=$($BTC_CLI -rpcwallet=keymeld_coordinator getnewaddress)
        $BTC_CLI generatetoaddress 6 $addr >/dev/null
        confirm_end_time=$(date +%s.%3N)
        confirm_duration=$(echo "scale=2; $confirm_end_time - $confirm_start_time" | bc)
        echo "   ✓ Batch $((batch_num + 1)) confirmed in ${confirm_duration}s"
    fi
done

# Final confirmation for last batch
echo "   Confirming final batch..."
final_confirm_start=$(date +%s.%3N)
addr=$($BTC_CLI -rpcwallet=keymeld_coordinator getnewaddress)
$BTC_CLI generatetoaddress 6 $addr >/dev/null

# Cleanup: Unload all test wallets to free memory
for i in $(seq 0 $((COUNT - 1))); do
    $BTC_CLI unloadwallet "stress_test_$i" >/dev/null 2>&1 || true
done

final_confirm_end=$(date +%s.%3N)
final_confirm_duration=$(echo "scale=2; $final_confirm_end - $final_confirm_start" | bc)

end_time=$(date +%s.%3N)
total_duration=$(echo "scale=2; $end_time - $start_time" | bc)
funding_duration=$(echo "scale=2; $end_time - $funding_start_time" | bc)

echo "   ✓ Final confirmation completed in ${final_confirm_duration}s"
echo "   ✓ All $COUNT wallets funded and confirmed in ${total_duration}s"
echo "     - Wallet creation: ${creation_duration}s"
echo "     - Funding + confirmations: ${funding_duration}s"
