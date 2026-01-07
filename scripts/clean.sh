#!/usr/bin/env bash
# Clean all KeyMeld data and stop services
set -euo pipefail

echo "🧹 Cleaning all data..."
echo "🛑 Stopping VSock proxy services..."
pkill -f keymeld-gateway || true
pkill -f keymeld-enclave || true
pkill -f bitcoind || true
pkill -f moto_server || true
vsock-proxy stop >/dev/null 2>&1 || true
echo "✅ All VSock proxy services stopped"
rm -rf data logs target/debug/keymeld-* result
mkdir -p data logs
echo "✅ Clean complete"
