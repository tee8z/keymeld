# KeyMeld MuSig2 Distributed Signing System
# Nix-based development and deployment

# Default recipe - show help
default:
    @just help

# Show available recipes
help:
    @echo "KeyMeld MuSig2 Distributed Signing System"
    @echo "========================================="
    @echo ""
    @echo "🚀 Quick Start:"
    @echo "  quickstart          Complete setup + plain demo (auto VSock setup)"
    @echo "  quickstart-adaptors Complete setup + adaptor signatures demo (auto VSock setup)"
    @echo ""
    @echo "📋 Service Management:"
    @echo "  start               Start all services"
    @echo "  stop                Stop all services"
    @echo "  restart             Restart all services"
    @echo "  status              Check service health"
    @echo ""
    @echo "🎮 Demo & Testing:"
    @echo "  demo [amount] [dest] Run MuSig2 demo with optional params"
    @echo "  demo-adaptors       Run adaptor signatures demo"
    @echo "  test-dlctix-batch   Run DLC batch signing E2E test"
    @echo "  test-single-signer  Run single-signer E2E test"
    @echo "  test-kms-e2e        Run KMS end-to-end tests with restart"
    @echo "  test-ui             Run Playwright UI tests (services must be running)"
    @echo "  test-ui-e2e         Run full UI E2E test (starts services automatically)"
    @echo "  mine <blocks>       Mine Bitcoin regtest blocks"
    @echo "  setup-regtest       Setup Bitcoin regtest environment"
    @echo ""
    @echo "🔧 Development:"
    @echo "  build               Build all services"
    @echo "  build-prod          Build production packages (pure Nix)"
    @echo "  test                Run tests"
    @echo "  fmt                 Format code"
    @echo "  lint                Lint code"
    @echo "  check               Run all checks (fmt + lint + test)"
    @echo ""
    @echo "☁️ AWS CI/CD Workflow:"
    @echo "  build-eif           [CI/CD] Build and upload AWS Nitro Enclave image"
    @echo "  deploy-aws          [Production] Download EIF and deploy to AWS"
    @echo "  gateway-aws         [Production] Start gateway for AWS deployment"
    @echo "  stop-aws            [Production] Stop AWS enclaves and cleanup"
    @echo ""
    @echo "🧹 Maintenance:"
    @echo "  clean               Clean all data (works for quickstart & stress tests)"
    @echo "  reset-cache         Reset Nix build cache"
    @echo "  kms <cmd>           Manage KMS service (start|stop|status|clean)"
    @echo "  vsock-proxy <cmd>   Manage VSock proxy services (start|stop|status)"
    @echo "  logs <service>      Show logs for specific service"
    @echo ""
    @echo "ℹ️ Information:"
    @echo "  info                Show system information"
    @echo "  dev                 Enter development shell"
    @echo ""
    @echo "📚 Prerequisites:"
    @echo "  - Nix package manager (curl -L https://nixos.org/nix/install | sh)"
    @echo "  - All other dependencies handled by Nix automatically"

# ==================================================================================
# Quick Start & Service Management
# ==================================================================================

# Complete setup + plain demo for new users
quickstart:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "🚀 Starting KeyMeld quickstart..."
    QUIET=true ./scripts/setup-vsock-sudoers.sh || echo "⚠️  VSock setup failed, continuing with fallback mode..."

    # Clean first (respects SKIP_BUILD to preserve pre-built binaries)
    ./scripts/clean.sh

    # Build unless SKIP_BUILD is set and all binaries exist
    if [ -z "${SKIP_BUILD:-}" ] || [ ! -f target/debug/keymeld-gateway ] || [ ! -f target/debug/keymeld-enclave ] || [ ! -f target/debug/keymeld_demo ]; then
        echo "Building binaries..."
        if [ -n "${IN_NIX_SHELL:-}" ]; then
            cargo build
        else
            nix develop -c cargo build
        fi
    else
        echo "Using pre-built binaries (SKIP_BUILD=1)"
    fi

    # If already in nix shell, run directly; otherwise wrap with nix develop
    if [ -n "${IN_NIX_SHELL:-}" ]; then
        QUIET=true ./scripts/vsock-setup.sh start && \
        ./scripts/setup-regtest.sh && \
        ./scripts/start-services.sh && \
        ./scripts/run-demo.sh plain 50000 bcrt1qf0p0zqynlcq7c4j6vm53qaxapm3chufwfgge80
    else
        nix develop -c bash -c '\
            QUIET=true ./scripts/vsock-setup.sh start && \
            ./scripts/setup-regtest.sh && \
            ./scripts/start-services.sh && \
            ./scripts/run-demo.sh plain 50000 bcrt1qf0p0zqynlcq7c4j6vm53qaxapm3chufwfgge80 \
        '
    fi

# Complete setup + adaptor signatures demo for new users
quickstart-adaptors:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "🚀 Starting KeyMeld adaptor signatures quickstart..."
    echo "🔧 Setting up VSock (CI-friendly, no password prompts)..."
    QUIET=true ./scripts/setup-vsock-sudoers.sh || echo "⚠️  VSock setup failed, continuing with fallback mode..."

    # Clean first (respects SKIP_BUILD to preserve pre-built binaries)
    ./scripts/clean.sh

    # Build unless SKIP_BUILD is set and all binaries exist
    if [ -z "${SKIP_BUILD:-}" ] || [ ! -f target/debug/keymeld-gateway ] || [ ! -f target/debug/keymeld-enclave ] || [ ! -f target/debug/keymeld_demo ]; then
        echo "Building binaries..."
        if [ -n "${IN_NIX_SHELL:-}" ]; then
            cargo build
        else
            nix develop -c cargo build
        fi
    else
        echo "Using pre-built binaries (SKIP_BUILD=1)"
    fi

    # If already in nix shell, run directly; otherwise wrap with nix develop
    if [ -n "${IN_NIX_SHELL:-}" ]; then
        QUIET=true ./scripts/vsock-setup.sh start && \
        ./scripts/setup-regtest.sh && \
        ./scripts/start-services.sh && \
        ./scripts/run-demo.sh adaptor 50000 bcrt1qf0p0zqynlcq7c4j6vm53qaxapm3chufwfgge80
    else
        nix develop -c bash -c '\
            QUIET=true ./scripts/vsock-setup.sh start && \
            ./scripts/setup-regtest.sh && \
            ./scripts/start-services.sh && \
            ./scripts/run-demo.sh adaptor 50000 bcrt1qf0p0zqynlcq7c4j6vm53qaxapm3chufwfgge80 \
        '
    fi

# Start all services
start: build-dev
    #!/usr/bin/env bash
    echo "🚀 Starting KeyMeld services..."
    # Create data directories
    mkdir -p data/bitcoin logs

    # Start Moto (AWS mock server for KMS) (if not already running)
    if ! pgrep -f moto_server > /dev/null; then
        echo "🔐 Starting Moto (KMS)..."
        nix run .#localstack > logs/localstack.log 2>&1 &
        sleep 5
        echo "✅ Moto started on port 4566"

        # Create KMS key in Moto with alias
        echo "🔑 Creating KMS key in Moto..."
        KEY_OUTPUT=$(AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-west-2 \
            aws --endpoint-url=http://localhost:4566 kms create-key \
            --description "KeyMeld Enclave Master Key" \
            --key-usage ENCRYPT_DECRYPT 2>&1)

        if echo "$KEY_OUTPUT" | grep -q "KeyId"; then
            KEY_ID=$(echo "$KEY_OUTPUT" | grep -o '"KeyId": "[^"]*"' | cut -d'"' -f4)
            echo "   Created key: $KEY_ID"

            # Create alias for the key
            AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-west-2 \
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

    # Start services in a single nix develop session to reduce overhead
    nix develop -c bash -c ' \
        # Start Bitcoin Core in regtest mode (if not already running) \
        if ! pgrep -f bitcoind > /dev/null; then \
            echo "Starting Bitcoin Core..."; \
            bitcoind -regtest -daemon -datadir=./data/bitcoin \
                -rpcuser=keymeld -rpcpassword=keymeldpass123 -rpcport=18443 \
                -port=18444 -fallbackfee=0.0001 -mintxfee=0.00001 \
                -txconfirmtarget=1 -blockmintxfee=0.00001 \
                -rpcthreads=128 -rpcworkqueue=512; \
            sleep 3; \
        else \
            echo "Bitcoin Core already running"; \
        fi; \
        \
        # Start KeyMeld Gateway \
        RUST_LOG=info KEYMELD_ENVIRONMENT=development \
            AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-west-2 \
            LD_LIBRARY_PATH=${CMAKE_LIBRARY_PATH:-} \
            ./target/debug/keymeld-gateway > logs/gateway.log 2>&1 & \
        \
        # Start KeyMeld Enclaves (simulated) - all 3 enclaves with VSock \
        for i in {0..2}; do \
            port=$((5000 + i)); \
            cid=2; \
            RUST_LOG=info ENCLAVE_ID=${i} ENCLAVE_CID=${cid} VSOCK_PORT=${port} \
                AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-west-2 \
                LD_LIBRARY_PATH=${CMAKE_LIBRARY_PATH:-} \
                ./target/debug/keymeld-enclave > logs/enclave-${i}.log 2>&1 & \
        done \
    '

    echo "✅ Services started! Logs available in logs/ directory"
    echo "🌐 Gateway: http://localhost:8090"
    echo "📊 Health: http://localhost:8090/api/v1/health"
    echo "🔗 VSock Proxies: localhost:9000-9002 → Enclaves 0-2"

# Stop all services
stop: stop-vsock-proxies
    #!/usr/bin/env bash
    echo "🛑 Stopping KeyMeld services..."
    # Use pgrep -x to match exact process names, avoiding parent shell matches
    for proc in keymeld-gateway keymeld-enclave keymeld_demo keymeld_session_test; do
        pgrep -x "$proc" 2>/dev/null | xargs -r kill 2>/dev/null || true
    done
    pkill -x moto_server || true
    # Stop bitcoind gracefully and wait for it to fully stop
    # Find bitcoind PIDs safely (nix wraps it as .bitcoind-wrapped, so we can't use pkill -x)
    # Use pgrep to find PIDs then kill individually to avoid matching parent shells
    bitcoind_pids=$(pgrep -f "bitcoind.*-regtest" 2>/dev/null | while read pid; do
        # Only include if it's actually a bitcoind process, not a shell containing the string
        if [[ "$(cat /proc/$pid/comm 2>/dev/null)" == *bitcoind* ]]; then
            echo "$pid"
        fi
    done)
    if [[ -n "$bitcoind_pids" ]]; then
        echo "   Stopping bitcoind..."
        echo "$bitcoind_pids" | xargs -r kill 2>/dev/null || true
        # Wait up to 10 seconds for graceful shutdown
        for i in {1..20}; do
            still_running=false
            for pid in $bitcoind_pids; do
                if kill -0 "$pid" 2>/dev/null; then
                    still_running=true
                    break
                fi
            done
            if ! $still_running; then
                break
            fi
            sleep 0.5
        done
        # Force kill if still running
        for pid in $bitcoind_pids; do
            if kill -0 "$pid" 2>/dev/null; then
                echo "   Force killing bitcoind (pid $pid)..."
                kill -9 "$pid" 2>/dev/null || true
            fi
        done
        sleep 1
    fi
    echo "✅ All services stopped"

# Restart all services
restart: stop start

# Check service health
status:
    #!/usr/bin/env bash
    echo "📊 KeyMeld Service Status:"
    echo "=========================="
    if pgrep -f moto_server > /dev/null; then
        echo "✅ Moto (KMS): Running (port 4566)"
    else
        echo "❌ Moto (KMS): Stopped"
    fi
    if pgrep -f bitcoind > /dev/null; then
        echo "✅ Bitcoin Core: Running"
    else
        echo "❌ Bitcoin Core: Stopped"
    fi
    if pgrep -f keymeld-gateway > /dev/null; then
        echo "✅ KeyMeld Gateway: Running"
    else
        echo "❌ KeyMeld Gateway: Stopped"
    fi
    enclave_count=$(pgrep -f keymeld-enclave | wc -l)
    if [ "$enclave_count" -gt 0 ]; then
        echo "✅ KeyMeld Enclaves: $enclave_count running"
    else
        echo "❌ KeyMeld Enclaves: None running"
    fi
    echo ""
    if command -v curl >/dev/null && curl --max-time 2 -fsS http://localhost:8090/api/v1/health >/dev/null 2>&1; then
        echo "🌐 Gateway Health Check: ✅ Healthy"
        curl --max-time 2 -fsS http://localhost:8090/api/v1/health | head -5
    else
        echo "🌐 Gateway Health Check: ❌ Unhealthy or not running"
    fi

# ==================================================================================
# Demo & Testing
# ==================================================================================

# Run MuSig2 demo with optional amount and destination
demo amount="50000" dest="bcrt1qf0p0zqynlcq7c4j6vm53qaxapm3chufwfgge80":
    @echo "🎮 Running KeyMeld MuSig2 Demo..."
    @nix develop -c ./scripts/run-demo.sh plain {{amount}} {{dest}}

# Run adaptor signatures demo
demo-adaptors amount="50000" dest="bcrt1qf0p0zqynlcq7c4j6vm53qaxapm3chufwfgge80":
    @echo "🔐 Running KeyMeld Adaptor Signatures Demo..."
    @nix develop -c ./scripts/run-demo.sh adaptor {{amount}} {{dest}}

# Run DLC batch signing E2E test
test-dlctix-batch:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "🎲 Running DLC Batch Signing E2E Test..."

    # Clean first
    ./scripts/clean.sh

    # Run everything in a single nix develop session to avoid multiple shell startups
    if [ -n "${IN_NIX_SHELL:-}" ]; then
        # Already in nix shell, run directly
        if [ -z "${SKIP_BUILD:-}" ] || [ ! -f target/debug/keymeld-gateway ] || [ ! -f target/debug/keymeld-enclave ] || [ ! -f target/debug/keymeld_demo ]; then
            echo "🔨 Building KeyMeld..."
            cargo build
        else
            echo "Using pre-built binaries (SKIP_BUILD=1)"
        fi
        echo "🚀 Starting services..."
        ./scripts/setup-regtest.sh
        ./scripts/start-services.sh
        echo "🎲 Running DLC batch signing E2E test..."
        cargo run --bin keymeld_demo -- dlctix --config config/example-nix.yaml
    else
        # Not in nix shell - run everything in a single nix develop session
        nix develop -c bash -c '
            if [ -z "${SKIP_BUILD:-}" ] || [ ! -f target/debug/keymeld-gateway ] || [ ! -f target/debug/keymeld-enclave ] || [ ! -f target/debug/keymeld_demo ]; then
                echo "🔨 Building KeyMeld..."
                cargo build
            else
                echo "Using pre-built binaries (SKIP_BUILD=1)"
            fi
            echo "🚀 Starting services..."
            ./scripts/setup-regtest.sh
            ./scripts/start-services.sh
            echo "🎲 Running DLC batch signing E2E test..."
            cargo run --bin keymeld_demo -- dlctix --config config/example-nix.yaml
        '
    fi

# Run single-signer E2E test
test-single-signer:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "🔑 Running Single-Signer E2E Test..."

    # Clean first
    ./scripts/clean.sh

    # Run everything in a single nix develop session to avoid multiple shell startups
    if [ -n "${IN_NIX_SHELL:-}" ]; then
        # Already in nix shell, run directly
        if [ -z "${SKIP_BUILD:-}" ] || [ ! -f target/debug/keymeld-gateway ] || [ ! -f target/debug/keymeld-enclave ] || [ ! -f target/debug/keymeld_demo ]; then
            echo "🔨 Building KeyMeld..."
            cargo build
        else
            echo "Using pre-built binaries (SKIP_BUILD=1)"
        fi
        echo "🚀 Starting services..."
        ./scripts/setup-regtest.sh
        ./scripts/start-services.sh
        echo "🔑 Running single-signer E2E test..."
        cargo run --bin keymeld_demo -- single-signer --config config/example-nix.yaml
    else
        # Not in nix shell - run everything in a single nix develop session
        nix develop -c bash -c '
            if [ -z "${SKIP_BUILD:-}" ] || [ ! -f target/debug/keymeld-gateway ] || [ ! -f target/debug/keymeld-enclave ] || [ ! -f target/debug/keymeld_demo ]; then
                echo "🔨 Building KeyMeld..."
                cargo build
            else
                echo "Using pre-built binaries (SKIP_BUILD=1)"
            fi
            echo "🚀 Starting services..."
            ./scripts/setup-regtest.sh
            ./scripts/start-services.sh
            echo "🔑 Running single-signer E2E test..."
            cargo run --bin keymeld_demo -- single-signer --config config/example-nix.yaml
        '
    fi

# Run parallel stress tests
stress mode count amount="50000":
    #!/usr/bin/env bash
    echo "🚀 Running KeyMeld stress test..."
    if [ -n "${IN_NIX_SHELL:-}" ]; then
        ./scripts/run-stress-test.sh {{mode}} {{count}} {{amount}}
    else
        nix develop -c ./scripts/run-stress-test.sh {{mode}} {{count}} {{amount}}
    fi

# Monitor stress test progress in real-time
stress-monitor interval="5":
    @echo "📊 Monitoring stress test..."
    @nix develop -c ./scripts/monitor-stress-test.sh {{interval}}

# Test wallet funding performance (requires Bitcoin regtest)
fund-wallets count amount="0.00055" batch_size="50" creation_parallelism="10":
    @echo "💰 Testing wallet funding with {{count}} wallets..."
    @nix develop -c bash -c 'scripts/setup-regtest.sh && scripts/fund-wallets.sh {{count}} {{amount}} {{batch_size}} {{creation_parallelism}}'

# Run KMS end-to-end tests (requires services to be running)
test-kms-e2e:
    #!/usr/bin/env bash
    echo "🧪 Running KMS End-to-End Tests..."
    if [ -n "${IN_NIX_SHELL:-}" ]; then
        ./scripts/test-kms-e2e.sh
    else
        nix develop -c ./scripts/test-kms-e2e.sh
    fi

# Mine Bitcoin regtest blocks
mine blocks="6":
    @echo "⛏️ Mining {{blocks}} regtest blocks..."
    nix develop -c bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        -generate {{blocks}}

# Setup Bitcoin regtest environment
setup-regtest:
    #!/usr/bin/env bash
    echo "🏦 Setting up Bitcoin regtest environment..."

    # Create directories first
    mkdir -p data/bitcoin logs

    # Ensure Bitcoin is running
    if ! pgrep -f bitcoind > /dev/null; then
        echo "Starting Bitcoin Core..."
        nix develop -c bitcoind -regtest -daemon -datadir=./data/bitcoin \
            -rpcuser=keymeld -rpcpassword=keymeldpass123 -rpcport=18443 \
            -port=18444 -fallbackfee=0.0001 -mintxfee=0.00001 \
            -rpcthreads=128 -rpcworkqueue=512
        echo "Waiting for Bitcoin Core to start..."
        sleep 5

        # Wait for RPC to be ready
        for i in {1..30}; do
            if nix develop -c bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 getblockchaininfo >/dev/null 2>&1; then
                echo "Bitcoin Core RPC ready"
                break
            fi
            echo "Waiting for Bitcoin Core RPC... ($i/30)"
            sleep 1
        done
    fi

    # Create wallet if it doesn't exist
    echo "Creating coordinator wallet..."
    nix develop -c bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        createwallet "keymeld_coordinator" >/dev/null 2>&1 || true

    # Load the wallet (in case it already existed but wasn't loaded)
    nix develop -c bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        loadwallet "keymeld_coordinator" >/dev/null 2>&1 || true

    # Generate initial blocks to coordinator
    echo "Generating initial blocks..."
    addr=$(nix develop -c bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        -rpcwallet=keymeld_coordinator getnewaddress)
    nix develop -c bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
        generatetoaddress 101 $addr > /dev/null

    echo "✅ Bitcoin regtest ready with funded coordinator wallet"

# ==================================================================================
# Development Commands
# ==================================================================================

# Build all services for development (incremental)
build-dev:
    nix develop -c cargo build

# Build all services (alias for build-dev)
build: build-dev

# Build production packages (pure Nix, reproducible)
build-prod:
    @echo "🏗️ Building production packages with pure Nix..."
    nix build .#keymeld-gateway
    nix build .#keymeld-enclave
    @echo "✅ Production builds complete in ./result/"

# Run tests
test:
    @echo "🧪 Running tests..."
    nix develop -c cargo test

# Format code
fmt:
    @echo "🎨 Formatting code..."
    nix develop -c cargo fmt

# Lint code
lint:
    @echo "🔍 Linting code..."
    nix develop -c cargo clippy

# Run all checks
check: fmt lint test
    @echo "✅ All checks passed!"

# Run Playwright UI tests (requires services to be running)
test-ui:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "🎭 Running Playwright UI tests..."
    cd e2e
    if [ ! -d "node_modules" ]; then
        echo "📦 Installing Playwright dependencies..."
        npm install
        npx playwright install chromium
    fi
    npx playwright test

# Run Playwright UI tests in headed mode (for debugging)
test-ui-headed:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "🎭 Running Playwright UI tests (headed)..."
    cd e2e
    if [ ! -d "node_modules" ]; then
        echo "📦 Installing Playwright dependencies..."
        npm install
        npx playwright install chromium
    fi
    npx playwright test --headed

# Run full UI E2E test (starts services, runs tests, stops services)
test-ui-e2e:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "🎭 Running full UI E2E test..."

    # Clean first
    ./scripts/clean.sh

    # The admin UI is disabled until an operator credential is configured.
    test_operator_token_file=$(mktemp)
    trap 'rm -f "$test_operator_token_file"' EXIT
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "$test_operator_token_file"
    export KEYMELD_OPERATOR_TOKEN_FILE="$test_operator_token_file"

    # Run everything in a single nix develop session
    if [ -n "${IN_NIX_SHELL:-}" ]; then
        if [ -z "${SKIP_BUILD:-}" ] || [ ! -f target/debug/keymeld-gateway ] || [ ! -f target/debug/keymeld-enclave ]; then
            echo "🔨 Building KeyMeld..."
            cargo build
        else
            echo "Using pre-built binaries (SKIP_BUILD=1)"
        fi
        echo "🚀 Starting services..."
        ./scripts/setup-regtest.sh
        ./scripts/start-services.sh
        echo "⏳ Waiting for gateway to be ready..."
        for i in {1..30}; do
            if curl --max-time 2 -fsS http://localhost:8090/api/v1/health > /dev/null 2>&1; then
                echo "✅ Gateway ready"
                break
            fi
            echo "Waiting for gateway... ($i/30)"
            sleep 1
        done
        echo "🎭 Running Playwright tests..."
        cd e2e
        if [ ! -d "node_modules" ]; then
            npm install
            npx playwright install chromium
        fi
        npx playwright test
    else
        nix develop -c bash -c '
            if [ -z "${SKIP_BUILD:-}" ] || [ ! -f target/debug/keymeld-gateway ] || [ ! -f target/debug/keymeld-enclave ]; then
                echo "🔨 Building KeyMeld..."
                cargo build
            else
                echo "Using pre-built binaries (SKIP_BUILD=1)"
            fi
            echo "🚀 Starting services..."
            ./scripts/setup-regtest.sh
            ./scripts/start-services.sh
            echo "⏳ Waiting for gateway to be ready..."
            for i in {1..30}; do
                if curl --max-time 2 -fsS http://localhost:8090/api/v1/health > /dev/null 2>&1; then
                    echo "✅ Gateway ready"
                    break
                fi
                echo "Waiting for gateway... ($i/30)"
                sleep 1
            done
            echo "🎭 Running Playwright tests..."
            cd e2e
            if [ ! -d "node_modules" ]; then
                npm install
                npx playwright install chromium
            fi
            npx playwright test
        '
    fi

# Enter development shell
dev:
    @echo "🚀 Entering Nix development shell..."
    nix develop

# Run KeyMeld services in background (gateway, moto/KMS, enclaves)
run:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "🚀 Starting KeyMeld services..."

    # Clean old data to avoid KMS key mismatch issues
    echo "🧹 Cleaning old data..."
    rm -rf data/keymeld.db data/keymeld.db-* logs/*.log 2>/dev/null || true
    mkdir -p data logs

    # Build if binaries don't exist
    if [ ! -f target/debug/keymeld-gateway ] || [ ! -f target/debug/keymeld-enclave ]; then
        echo "🔨 Building binaries..."
        if [ -n "${IN_NIX_SHELL:-}" ]; then
            cargo build
        else
            nix develop -c cargo build
        fi
    fi

    # Start services
    if [ -n "${IN_NIX_SHELL:-}" ]; then
        ./scripts/start-services.sh
    else
        nix develop -c ./scripts/start-services.sh
    fi

    echo ""
    echo "🎉 KeyMeld is running in the background!"
    echo "   Gateway: http://localhost:8090"
    echo "   Health:  http://localhost:8090/api/v1/health"
    echo "   Logs:    logs/"
    echo ""
    echo "Run 'just down' to stop all services."

# Stop all KeyMeld services (alias for stop)
down: stop

# ==================================================================================
# Maintenance & Utilities
# ==================================================================================

# Clean all data and rebuild database (works for both quickstart and stress tests)
clean: stop
    #!/usr/bin/env bash
    echo "🧹 Cleaning all KeyMeld data..."

    # Ensure all processes are stopped (use pgrep -x to avoid killing parent shell)
    for proc in keymeld-gateway keymeld-enclave keymeld_demo keymeld_session_test; do
        pgrep -x "$proc" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    done
    pkill -9 -x haproxy 2>/dev/null || true
    ./scripts/bitcoin-rpc-batcher.sh stop 2>/dev/null || true
    rm -rf /tmp/keymeld-bitcoin-proxy 2>/dev/null || true
    rm -rf /tmp/keymeld-rpc-queue 2>/dev/null || true
    rm -f /tmp/keymeld-rpc-batcher.pid /tmp/keymeld-rpc-batcher.log 2>/dev/null || true
    sleep 1

    # Remove all data, logs, and build artifacts
    rm -rf data logs result
    rm -rf /tmp/keymeld-stress-test
    # Only clean binaries if not using pre-built (CI sets SKIP_BUILD)
    if [ -z "${SKIP_BUILD:-}" ]; then
        rm -rf target/debug/keymeld-* target/debug/keymeld_*
    fi

    # Recreate necessary directories
    mkdir -p data logs

    # Clean KMS data
    rm -rf ./data/kms-data
    rm -f ./data/kms-seed.yaml

    echo "✅ Complete clean finished - ready for quickstart or stress tests"

# ==================================================================================
# KMS (Key Management Service)
# ==================================================================================

# Manage Moto KMS service (start|stop|status|clean)
kms cmd:
    #!/usr/bin/env bash
    case "{{cmd}}" in
        start)
            echo "🔐 Starting Moto (KMS)..."
            if pgrep -f moto_server > /dev/null; then
                echo "⚠️  Moto already running"
                exit 0
            fi
            mkdir -p logs
            nix run .#localstack > logs/localstack.log 2>&1 &
            sleep 3
            echo "✅ Moto started on port 4566"
            ;;
        stop)
            echo "🛑 Stopping Moto..."
            pkill -f moto_server || true
            echo "✅ Moto stopped"
            ;;
        status)
            echo "📊 Moto KMS Status:"
            if pgrep -f moto_server > /dev/null; then
                echo "  Moto: ✅ Running (PID: $(pgrep -f moto_server))"
                echo "  Endpoint: http://127.0.0.1:4566"
            else
                echo "  Moto: ❌ Not running"
            fi
            ;;
        clean)
            echo "🧹 Cleaning Moto data..."
            rm -rf ./data/localstack
            echo "✅ Moto data cleaned"
            ;;
        *)
            echo "Usage: just kms {start|stop|status|clean}"
            exit 1
            ;;
    esac

# ==================================================================================
# Nix Cache & System
# ==================================================================================

# Reset Nix build cache (fix SQLite conflicts)
reset-cache:
    @echo "🔄 Resetting Nix eval cache..."
    rm -rf ~/.cache/nix/eval-cache-v*
    @echo "✅ Cache reset complete"

# Show logs for specific service
logs service:
    @if [ -f "logs/{{service}}.log" ]; then \
        echo "📋 Showing logs for {{service}}:"; \
        tail -f logs/{{service}}.log; \
    else \
        echo "❌ No logs found for {{service}}"; \
        echo "Available logs:"; \
        ls logs/ 2>/dev/null || echo "No logs directory"; \
    fi

# Show system information
info:
    #!/usr/bin/env bash
    echo "ℹ️ KeyMeld System Information"
    echo "============================"
    echo ""
    echo "🔧 Nix:"
    if command -v nix >/dev/null 2>&1; then
        echo "  Status: ✅ Available"
        echo "  Version: $(nix --version)"
    else
        echo "  Status: ❌ Not available"
        echo "  Install: curl -L https://nixos.org/nix/install | sh"
    fi
    echo ""
    echo "🦀 Rust (in Nix shell):"
    nix develop -c bash -c 'echo "  Version: $(rustc --version)"'
    echo ""
    echo "₿ Bitcoin:"
    if pgrep -f bitcoind > /dev/null; then
        echo "  Status: ✅ Running"
        nix develop -c bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 \
            getblockchaininfo 2>/dev/null | head -5 || echo "  RPC: Not responding"
    else
        echo "  Status: ❌ Not running"
    fi
    echo ""
    echo "🌐 Gateway:"
    if pgrep -f keymeld-gateway > /dev/null; then
        echo "  Status: ✅ Running on http://localhost:8090"
    else
        echo "  Status: ❌ Not running"
    fi
    echo ""
    echo "🔒 VSock:"
    if [ -e /dev/vsock ]; then
        echo "  Status: ✅ Available"
        ls -la /dev/vsock 2>/dev/null | tail -1 || echo "  Device: /dev/vsock exists"
    else
        echo "  Status: ❌ Not available"
        echo "  Setup: Run 'just setup-vsock' to enable VSock simulation"
    fi
    echo ""
    echo "🔒 Enclaves:"
    enclave_count=$(pgrep -f keymeld-enclave | wc -l)
    echo "  Running: $enclave_count/3"

# Show Nix flake information
nix-info:
    @echo "📦 Nix Flake Information:"
    nix flake show

# Update flake inputs
nix-update:
    @echo "⬆️ Updating Nix flake inputs..."
    nix flake update
    @echo "✅ Flake updated"

# ==================================================================================
# AWS Nitro Enclave Deployment
# ==================================================================================

# CI/CD: Build AWS Nitro Enclave image (EIF) and optionally upload to S3
build-eif:
    @echo "🏗️ [CI/CD] Building and uploading AWS Nitro Enclave image..."
    nix run .#build-eif

# Production: Download EIF and deploy to AWS Nitro Enclaves with CID discovery
deploy-aws:
    @echo "🚀 [Production] Deploying KeyMeld to AWS Nitro Enclaves..."
    nix run .#deploy-aws

# Production: Start gateway configured for AWS Nitro Enclaves
gateway-aws:
    @echo "🌐 [Production] Starting KeyMeld Gateway for AWS..."
    nix run .#gateway-aws

# Production: Stop AWS Nitro Enclaves and cleanup
stop-aws:
    @echo "🛑 [Production] Stopping AWS Nitro Enclaves..."
    nix run .#stop-aws

# Start VSock proxy services
start-vsock-proxies:
    @echo "🚀 Starting VSock proxy services..."
    nix develop -c vsock-proxy start

# Stop VSock proxy services
stop-vsock-proxies:
    @echo "🛑 Stopping VSock proxy services..."
    nix develop -c vsock-proxy stop

# Manage VSock proxy services
vsock-proxy cmd:
    nix develop -c vsock-proxy {{cmd}}
