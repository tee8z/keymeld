#!/usr/bin/env bash
# Monitor stress test progress in real-time
#
# Usage: ./scripts/monitor-stress-test.sh [interval_secs]
#
# Shows: wallet creation, demo processes, completion status, queue depths, HAProxy sessions

set -uo pipefail

# Get the repo root directory (parent of scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

INTERVAL="${1:-5}"

echo "Monitoring stress test (refresh every ${INTERVAL}s)... Press Ctrl+C to stop"
echo ""

# Wait for stress test to start
if ! pgrep -f "stress-test.sh" > /dev/null 2>&1; then
  echo "Waiting for stress test to start..."
  while ! pgrep -f "stress-test.sh" > /dev/null 2>&1; do
    sleep 1
  done
  echo "Stress test detected, monitoring..."
  echo ""
fi

while true; do
  # Count wallets - check both wallet directories and loaded wallets via RPC
  wallets_dir=$(ls -d "$REPO_ROOT/data/bitcoin/regtest/wallets/stress_test_"* 2>/dev/null | wc -l | tr -d ' ' || echo 0)
  wallets_loaded=$(bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 listwallets 2>/dev/null | grep -c stress_test 2>/dev/null || echo 0)
  # Trim whitespace and ensure numeric
  wallets_dir="${wallets_dir//[^0-9]/}"
  wallets_loaded="${wallets_loaded//[^0-9]/}"
  wallets_dir="${wallets_dir:-0}"
  wallets_loaded="${wallets_loaded:-0}"
  wallets=$((wallets_dir > wallets_loaded ? wallets_dir : wallets_loaded))

  completed=$(ls /tmp/keymeld-stress-test/exit-*.code 2>/dev/null | wc -l | tr -d ' \n')
  demos=$(pgrep -c -x keymeld_demo 2>/dev/null || echo 0)
  demos="${demos//[$'\n\r']/}"

  # Detect total from config files created by stress test
  total=$(ls /tmp/keymeld-stress-test/config-*.yaml 2>/dev/null | wc -l | tr -d ' \n')
  if [[ "$total" -eq 0 ]]; then
    total="?"
  fi

  # Queue depths (only used for high-concurrency tests with 100+ instances)
  funding_q=$(ls /tmp/keymeld-rpc-queue/funding/requests/*.req 2>/dev/null | wc -l | tr -d ' \n')
  confirm_q=$(ls /tmp/keymeld-rpc-queue/confirm/requests/*.req 2>/dev/null | wc -l | tr -d ' \n')

  # HAProxy stats
  haproxy_stats=$(curl -s "http://127.0.0.1:18480/;csv" 2>/dev/null | grep "bitcoin_rpc_backend,bitcoind" || echo "")
  if [[ -n "$haproxy_stats" ]]; then
    sessions=$(echo "$haproxy_stats" | awk -F',' '{print $8}')
  else
    sessions="-"
  fi

  echo "$(date +%H:%M:%S) | Wallets: $wallets | Demos: $demos | Done: $completed/$total | FundQ: $funding_q | ConfirmQ: $confirm_q | HAProxy Sessions: $sessions"

  # Check if test finished
  if ! pgrep -f "stress-test.sh" > /dev/null 2>&1; then
    echo ""
    echo "=== Test Finished ==="

    # Final summary
    total=$(ls /tmp/keymeld-stress-test/exit-*.code 2>/dev/null | wc -l)
    success=0
    failed=0
    for f in /tmp/keymeld-stress-test/exit-*.code; do
      code=$(cat "$f" 2>/dev/null)
      if [[ "$code" == "0" ]]; then
        success=$((success + 1))
      elif [[ -n "$code" ]]; then
        failed=$((failed + 1))
      fi
    done

    echo "Total: $total | Passed: $success | Failed: $failed"
    if [[ $total -gt 0 ]]; then
      pct=$(echo "scale=1; $success * 100 / $total" | bc)
      echo "Success Rate: ${pct}%"
    fi
    break
  fi

  sleep "$INTERVAL"
done
