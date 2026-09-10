#!/usr/bin/env bash
# Start KeyMeld gateway and enclave services
set -euo pipefail

keymeld_repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd -- "$keymeld_repo_root"
source "$keymeld_repo_root/scripts/development-auth.sh"

# Increase file descriptor limit for high concurrency
# Gateway needs many FDs for concurrent HTTP connections
ulimit -n 65536 2>/dev/null || true

echo "🚀 Starting KeyMeld services..."
mkdir -p data logs
LD_LIBRARY_PATH=${CMAKE_LIBRARY_PATH:-} \
    keymeld_setup_development_auth "$keymeld_repo_root" "$keymeld_repo_root/target/debug/keymeld-gateway"

# Start LocalStack (if not already running)
if ! pgrep -f moto_server > /dev/null; then
    echo "🔐 Starting Moto (KMS)..."
    nix run .#localstack > logs/localstack.log 2>&1 &
    sleep 5
    echo "✅ Moto started on port 4566"

    # Create KMS key in Moto with alias
    echo "🔑 Creating KMS key in Moto..."
    KEY_OUTPUT=$(env -u LD_LIBRARY_PATH AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-west-2 \
        aws --endpoint-url=http://localhost:4566 kms create-key \
        --description "KeyMeld Enclave Master Key" \
        --key-usage ENCRYPT_DECRYPT 2>&1)

    if echo "$KEY_OUTPUT" | grep -q "KeyId"; then
        KEY_ID=$(echo "$KEY_OUTPUT" | grep -o '"KeyId": "[^"]*"' | cut -d'"' -f4)
        echo "   Created key: $KEY_ID"

        # Create alias for the key
        env -u LD_LIBRARY_PATH AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-west-2 \
            aws --endpoint-url=http://localhost:4566 kms create-alias \
            --alias-name alias/keymeld-enclave-master-key \
            --target-key-id "$KEY_ID" 2>&1 || echo "   Alias might already exist"
        echo "   ✅ KMS key ready: alias/keymeld-enclave-master-key"
    else
        echo "   ⚠️  KMS key might already exist"
    fi
else
    echo "✅ Moto already running"
fi

# Set AWS credentials for LocalStack
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-west-2

# Start KeyMeld Enclaves (simulated) - all 3 enclaves with VSock
for i in {0..2}; do
    port=$((5000 + i))
    cid=2  # Host CID for local VSock simulation
    RUST_LOG=info ENCLAVE_ID=${i} ENCLAVE_CID=${cid} VSOCK_PORT=${port} \
        LD_LIBRARY_PATH=${CMAKE_LIBRARY_PATH:-} \
        AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-west-2 \
        ./target/debug/keymeld-enclave > logs/enclave-${i}.log 2>&1 &
done

# Gateway startup authenticates every enclave before accepting HTTP requests.
sleep 1
RUST_LOG=info CONFIG_PATH="$keymeld_repo_root/config/development.yaml" \
    KEYMELD_HOST=127.0.0.1 LD_LIBRARY_PATH=${CMAKE_LIBRARY_PATH:-} \
    AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-west-2 \
    ./target/debug/keymeld-gateway > logs/gateway.log 2>&1 &

echo "✅ Services started! Logs available in logs/ directory"
echo "🌐 Gateway: http://localhost:8090"

# Wait for gateway to be ready
echo "⏳ Waiting for gateway to be ready..."
for i in {1..30}; do
    if curl --max-time 2 -fsS http://localhost:8090/api/v1/health > /dev/null 2>&1; then
        echo "✅ Gateway is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ Gateway failed to start within 30 seconds"
        echo "📋 Gateway logs:"
        tail -20 logs/gateway.log
        exit 1
    fi
    sleep 1
done

# Wait for enclaves to be ready
echo "⏳ Waiting for enclaves to initialize..."
sleep 3
