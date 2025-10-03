#!/bin/bash
set -e

echo "🐳 Starting KeyMeld Gateway..."

# Setup database directory
DATABASE_PATH=${KEYMELD_DATABASE_PATH:-/data/keymeld.db}

# Create database directory
mkdir -p "$(dirname "$DATABASE_PATH")"

echo "🗄️ Database directory ready (migrations will be handled by application)"
echo "🚀 Starting gateway service..."

# Start gateway
exec keymeld-gateway "$@"
