#!/usr/bin/env bash
# Clean all KeyMeld data and stop services
set -euo pipefail

echo "🧹 Cleaning all data..."
pkill -f keymeld-gateway || true
pkill -f keymeld-enclave || true
pkill -f bitcoind || true
vsock-proxy stop 2>/dev/null || true
rm -rf data logs target/debug/keymeld-* result
mkdir -p data logs
echo "✅ Clean complete"
