#!/usr/bin/env bash
# Start KeyMeld gateway and enclave services
set -euo pipefail

echo "🚀 Starting KeyMeld services..."
mkdir -p data logs

# Start KeyMeld Gateway
RUST_LOG=info KEYMELD_ENVIRONMENT=development LD_LIBRARY_PATH=${CMAKE_LIBRARY_PATH:-} \
    ./target/debug/keymeld-gateway > logs/gateway.log 2>&1 &

# Start KeyMeld Enclaves (simulated) - all 3 enclaves with VSock
for i in {0..2}; do
    port=$((5000 + i))
    cid=2  # Host CID for local VSock simulation
    RUST_LOG=info ENCLAVE_ID=${i} ENCLAVE_CID=${cid} VSOCK_PORT=${port} \
        LD_LIBRARY_PATH=${CMAKE_LIBRARY_PATH:-} \
        ./target/debug/keymeld-enclave > logs/enclave-${i}.log 2>&1 &
done

echo "✅ Services started! Logs available in logs/ directory"
echo "🌐 Gateway: http://localhost:8080"
