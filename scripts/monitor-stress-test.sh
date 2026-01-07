#!/usr/bin/env bash
# Monitor stress test progress in real-time
#
# Usage: ./scripts/monitor-stress-test.sh [interval_secs]
#
# Shows: wallet creation, demo processes, completion status, queue depths, HAProxy sessions

set -uo pipefail

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
  wallets=$(ls data/bitcoin/regtest/wallets/ 2>/dev/null | grep stress_test | wc -l)
  completed=$(ls /tmp/keymeld-stress-test/exit-*.code 2>/dev/null | wc -l)
  demos=$(ps aux | grep keymeld_demo | grep -v grep | wc -l)

  # Queue depths
  funding_req=$(ls /tmp/keymeld-rpc-queue/funding/requests/*.req 2>/dev/null | wc -l)
  confirm_req=$(ls /tmp/keymeld-rpc-queue/confirm/requests/*.req 2>/dev/null | wc -l)

  # HAProxy stats
  haproxy_stats=$(curl -s "http://127.0.0.1:18480/;csv" 2>/dev/null | grep "bitcoin_rpc_backend,bitcoind" || echo "")
  if [[ -n "$haproxy_stats" ]]; then
    sessions=$(echo "$haproxy_stats" | awk -F',' '{print $8}')
  else
    sessions="-"
  fi

  echo "$(date +%H:%M:%S) | Wallets: $wallets | Demos: $demos | Done: $completed/1000 | Funding: $funding_req | Confirm: $confirm_req | Sessions: $sessions"

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
