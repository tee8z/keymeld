# Default recipe
default:
    @just --list

# Show available recipes
help:
    @echo "KeyMeld MuSig2 Distributed Signing System"
    @echo "========================================="
    @echo ""
    @echo "🚀 Quick Start:"
    @echo "  just quickstart              - Complete setup and run demo"
    @echo "  just quickstart <amount> true - Quickstart with rebuild"
    @echo "  just demo [amount] [dest]    - Run demo with custom parameters"
    @echo ""
    @echo "🔧 Services:"
    @echo "  just start                   - Start all services"
    @echo "  just rebuild                 - Rebuild and start all KeyMeld containers"
    @echo "  just restart                 - Stop and restart all services (no rebuild)"
    @echo "  just stop                    - Stop all services"
    @echo "  just status                  - Check service health"
    @echo "  just logs [service]          - View service logs"
    @echo ""
    @echo "💰 Bitcoin (regtest):"
    @echo "  just mine <blocks>           - Mine regtest blocks"
    @echo ""
    @echo "🧹 Cleanup:"
    @echo "  just clean                   - Stop and remove all data"

# ==================================================================================
# Quick Start - Main Entry Point
# ==================================================================================

# Complete quickstart: build, start services, setup, and run demo
quickstart amount="50000" rebuild="false":
    #!/usr/bin/env bash
    echo "🚀 KeyMeld Quickstart"
    echo "===================="

    if [ "{{rebuild}}" = "true" ]; then
        echo "🔨 Rebuilding containers..."
        just rebuild
    else
        echo "🗄️ Ensuring database exists..."
        mkdir -p ./data
        if [ ! -f "./data/keymeld.db" ]; then
            cd crates/keymeld-gateway && sqlx database create --database-url sqlite:../../data/keymeld.db
            cd crates/keymeld-gateway && sqlx migrate run --database-url sqlite:../../data/keymeld.db
            echo "✅ Database created and migrated"
        else
            echo "✅ Database already exists"
        fi
        just start
    fi

    just setup-regtest
    just fund-coordinator
    just _demo-no-deps {{amount}}

# ==================================================================================
# Service Management
# ==================================================================================

# Start all KeyMeld services
start:
    #!/usr/bin/env bash
    echo "🐳 Starting KeyMeld services (development)..."
    echo "🗄️ Ensuring database exists..."
    mkdir -p ./data
    if [ ! -f "./data/keymeld.db" ]; then
        cd crates/keymeld-gateway && sqlx database create --database-url sqlite:../../data/keymeld.db
        cd crates/keymeld-gateway && sqlx migrate run --database-url sqlite:../../data/keymeld.db
        echo "✅ Database created and migrated"
    else
        echo "✅ Database already exists"
    fi
    KEYMELD_ENV=dev docker compose up -d

    echo "⏳ Waiting for gateway to be ready..."
    for i in {1..60}; do
        if curl -sf http://localhost:8080/api/v1/health >/dev/null 2>&1; then
            echo "✅ KeyMeld Gateway ready!"
            break
        fi
        if [ $i -eq 60 ]; then
            echo "❌ Gateway not ready after 60 attempts"
            echo "Check logs with: just logs gateway"
            exit 1
        fi
        sleep 2
    done

    echo "✅ All services started and ready!"

# Rebuild all KeyMeld containers (gateway and enclaves) and start services
rebuild:
    #!/usr/bin/env bash
    echo "🔨 Rebuilding all KeyMeld containers..."
    echo "🗄️ Ensuring database exists..."
    mkdir -p ./data
    if [ ! -f "./data/keymeld.db" ]; then
        cd crates/keymeld-gateway && sqlx database create --database-url sqlite:../../data/keymeld.db
        cd crates/keymeld-gateway && sqlx migrate run --database-url sqlite:../../data/keymeld.db
        echo "✅ Database created and migrated"
    else
        echo "✅ Database already exists"
    fi

    echo "🛑 Stopping existing services..."
    docker compose down

    echo "🔨 Building KeyMeld containers with --no-cache..."
    KEYMELD_ENV=dev docker compose build --no-cache gateway enclave-0 enclave-1 enclave-2

    echo "🐳 Starting services..."
    KEYMELD_ENV=dev docker compose up -d

    echo "⏳ Waiting for gateway to be ready..."
    for i in {1..60}; do
        if curl -sf http://localhost:8080/api/v1/health >/dev/null 2>&1; then
            echo "✅ KeyMeld Gateway ready!"
            break
        fi
        if [ $i -eq 60 ]; then
            echo "❌ Gateway not ready after 60 attempts"
            echo "Check logs with: just logs gateway"
            exit 1
        fi
        sleep 2
    done

    echo "✅ All services rebuilt and ready!"

# Stop and restart all services without rebuilding
restart:
    #!/usr/bin/env bash
    echo "🔄 Restarting KeyMeld services..."
    echo "🛑 Stopping services..."
    docker compose down
    echo "🐳 Starting services..."
    just start
    echo "✅ All services restarted!"

# Stop all services
stop:
    @echo "🛑 Stopping KeyMeld services..."
    docker compose down

# Check service health
status:
    #!/usr/bin/env bash
    echo "🔍 Service Status:"

    # Check Gateway
    if curl -sf http://localhost:8080/api/v1/health >/dev/null 2>&1; then
        echo "✅ KeyMeld Gateway (http://localhost:8080)"
    else
        echo "❌ KeyMeld Gateway"
    fi

    # Check Bitcoin
    echo -n "Bitcoin Core: "
    if docker compose ps bitcoin | grep -q "running"; then
        echo "✅ Running"
    else
        echo "❌ Not running"
    fi

# View logs for a service or all services
logs service="":
    #!/usr/bin/env bash
    if [ -z "{{service}}" ]; then
        echo "📋 Viewing all service logs..."
        docker compose logs -f --tail=20
    else
        echo "📋 Viewing {{service}} logs..."
        docker compose logs -f --tail=20 {{service}}
    fi

# ==================================================================================
# Demo Commands
# ==================================================================================

# Run KeyMeld demo on regtest
demo amount="50000" destination="":
    #!/usr/bin/env bash
    if ! curl -sf http://localhost:8080/api/v1/health >/dev/null 2>&1; then
        echo "❌ KeyMeld not running. Start with: just start"
        exit 1
    fi

    # Generate destination address if not provided
    DEST_ADDR="{{destination}}"
    if [ -z "$DEST_ADDR" ]; then
        DEST_ADDR=$(docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 getnewaddress 2>/dev/null || echo "bcrt1qdeszrlqksxy5570x6taves23j6as32tn6glhap")
    fi

    echo "🔐 Running KeyMeld demo on regtest"
    echo "   Amount: {{amount}} sats"
    echo "   Destination: $DEST_ADDR"

    docker compose --profile example run --rm -T example \
        --config /app/config.yaml --amount {{amount}} --destination "$DEST_ADDR"

# Internal: Run demo without rebuilding dependencies (used by quickstart)
_demo-no-deps amount="50000" destination="":
    #!/usr/bin/env bash
    # Generate destination address if not provided
    DEST_ADDR="{{destination}}"
    if [ -z "$DEST_ADDR" ]; then
        DEST_ADDR=$(docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 getnewaddress 2>/dev/null || echo "bcrt1qdeszrlqksxy5570x6taves23j6as32tn6glhap")
    fi

    echo "🔐 Running KeyMeld demo on regtest"
    echo "   Amount: {{amount}} sats"
    echo "   Destination: $DEST_ADDR"

    # Use --no-deps to avoid rebuilding already-built services
    docker compose --profile example run --rm --no-deps -T example \
        --config /app/config.yaml --amount {{amount}} --destination "$DEST_ADDR"

# ==================================================================================
# Bitcoin Utilities
# ==================================================================================

# Setup regtest environment (mine initial blocks)
setup-regtest:
    @echo "⛏️ Setting up regtest environment..."
    just mine 101
    @echo "✅ Regtest ready with 101 blocks"

# Fund coordinator wallet with coins from Bitcoin Core
fund-coordinator:
    #!/usr/bin/env bash
    echo "💰 Setting up coordinator wallet in Bitcoin Core..."

    # Create the keys directory to ensure persistence
    mkdir -p /tmp/keymeld-keys

    # Create coordinator wallet in Bitcoin Core
    echo "📋 Creating coordinator wallet in Bitcoin Core..."
    docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        createwallet "keymeld_coordinator" >/dev/null 2>&1 || true

    # Load the coordinator wallet
    docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        loadwallet "keymeld_coordinator" >/dev/null 2>&1 || true

    # Get coordinator address from Bitcoin Core wallet
    COORD_ADDR=$(docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        -rpcwallet="keymeld_coordinator" getnewaddress 2>/dev/null | tr -d '\r')
    echo "🔑 Coordinator address: $COORD_ADDR"

    # Export the master extended private key from Bitcoin Core (Bitcoin Core 30.0+ method)
    echo "💾 Exporting coordinator master extended private key from Bitcoin Core..."
    XPRV=$(docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        -rpcwallet="keymeld_coordinator" gethdkeys '{"private":true}' | jq -r '.[0].xprv' 2>/dev/null | tr -d '\r')

    # Save the master extended private key to the example container
    echo "$XPRV" > /tmp/keymeld-keys/coordinator_master.key

    # Mine blocks directly to coordinator address
    echo "⛏️ Mining 101 blocks to coordinator address..."
    docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        generatetoaddress 101 "$COORD_ADDR" >/dev/null

    echo "✅ Coordinator wallet funded with mining rewards"
    echo "💾 Private key saved to: /tmp/keymeld-keys/coordinator_master.key"
    echo "🔑 Both Bitcoin Core and example will use the same private key"

# Mine regtest blocks
mine count:
    #!/usr/bin/env bash
    if ! docker compose ps bitcoin | grep -q "running"; then
        echo "❌ Bitcoin not running. Start with: just start"
        exit 1
    fi

    # Ensure coordinator wallet exists for mining
    docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        createwallet "keymeld_coordinator" >/dev/null 2>&1 || true

    docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        loadwallet "keymeld_coordinator" >/dev/null 2>&1 || true

    # Get mining address from coordinator wallet
    MINING_ADDR=$(docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        -rpcwallet="keymeld_coordinator" getnewaddress 2>/dev/null | tr -d '\r')

    echo "⛏️ Mining {{count}} blocks to $MINING_ADDR..."
    docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        generatetoaddress {{count}} "$MINING_ADDR" >/dev/null

    HEIGHT=$(docker compose exec -T bitcoin bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 getblockchaininfo | grep '"blocks"' | cut -d: -f2 | tr -d ' ,' | tr -d '\r')
    echo "✅ Mined {{count}} blocks (total: $HEIGHT)"

# ==================================================================================
# Cleanup and Utilities
# ==================================================================================

# Clean: stop services and remove all data
clean:
    @echo "🧹 Cleaning KeyMeld environment..."
    docker compose down -v
    rm -rf ./data
    rm -rf /tmp/keymeld-keys
    @echo "🗄️ Recreating database..."
    mkdir -p ./data
    cd crates/keymeld-gateway && sqlx database create --database-url sqlite:../../data/keymeld.db
    cd crates/keymeld-gateway && sqlx migrate run --database-url sqlite:../../data/keymeld.db
    @echo "✅ Cleanup complete with fresh database"
