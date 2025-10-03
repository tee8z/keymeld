#!/bin/bash
set -e

echo "Starting KeyMeld Example..."

# Wait for gateway to be ready
GATEWAY_URL=${GATEWAY_URL:-http://gateway:8080}
echo "Waiting for KeyMeld Gateway at $GATEWAY_URL..."

for i in {1..30}; do
    if curl -sf "$GATEWAY_URL/api/v1/health" >/dev/null 2>&1; then
        echo "Gateway is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "Gateway not available after 30 attempts"
        exit 1
    fi
    sleep 2
done

echo "Starting KeyMeld example..."
exec keymeld-example "$@" < /dev/null
