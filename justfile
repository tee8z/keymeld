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
    @echo "  quickstart          Complete setup + plain demo (new users start here)"
    @echo "  quickstart-adaptors Complete setup + adaptor signatures demo"
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
    nix develop -c bash -c '\
        ./scripts/clean.sh && \
        vsock-proxy start && \
        ./scripts/setup-regtest.sh && \
        cargo build && \
        ./scripts/start-services.sh && \
        ./scripts/run-demo.sh plain 50000 bcrt1qf0p0zqynlcq7c4j6vm53qaxapm3chufwfgge80 \
    '

# Complete setup + adaptor signatures demo for new users
quickstart-adaptors:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "🚀 Starting KeyMeld adaptor signatures quickstart..."
    nix develop -c bash -c '\
        ./scripts/clean.sh && \
        vsock-proxy start && \
        ./scripts/setup-regtest.sh && \
        cargo build && \
        ./scripts/start-services.sh && \
        ./scripts/run-demo.sh adaptor 50000 bcrt1qf0p0zqynlcq7c4j6vm53qaxapm3chufwfgge80 \
    '

# Start all services
start: build-dev
    #!/usr/bin/env bash
    echo "🚀 Starting KeyMeld services..."
    # Create data directory
    mkdir -p data logs

    # Start Bitcoin Core in regtest mode (if not already running)
    if ! pgrep -f bitcoind > /dev/null; then
        echo "Starting Bitcoin Core..."
        nix develop -c bitcoind -regtest -daemon -datadir=./data/bitcoin \
            -rpcuser=keymeld -rpcpassword=keymeldpass123 -rpcport=18443 \
            -port=18444 -fallbackfee=0.0001 -mintxfee=0.00001 \
            -txconfirmtarget=1 -blockmintxfee=0.00001
        sleep 3
    else
        echo "Bitcoin Core already running"
    fi

    # Start KeyMeld Gateway
    nix develop -c bash -c 'RUST_LOG=info KEYMELD_ENVIRONMENT=development \
        LD_LIBRARY_PATH=${CMAKE_LIBRARY_PATH:-} \
        ./target/debug/keymeld-gateway > logs/gateway.log 2>&1 &'

    # Start KeyMeld Enclaves (simulated) - all 3 enclaves with VSock
    # Note: All enclaves use CID 2 (host CID) in development. In production AWS Nitro Enclaves,
    # each would have a unique CID. Local simulation cannot use guest CIDs (3+) without real VMs.
    for i in {0..2}; do
        port=$((5000 + i))
        cid=2  # Host CID - required for local VSock simulation
        nix develop -c bash -c "RUST_LOG=info ENCLAVE_ID=${i} ENCLAVE_CID=${cid} VSOCK_PORT=${port} \
            LD_LIBRARY_PATH=\${CMAKE_LIBRARY_PATH:-} \
            ./target/debug/keymeld-enclave > logs/enclave-${i}.log 2>&1 &"
    done

    echo "✅ Services started! Logs available in logs/ directory"
    echo "🌐 Gateway: http://localhost:8080"
    echo "📊 Health: http://localhost:8080/health"
    echo "🔗 VSock Proxies: localhost:9000-9002 → Enclaves 0-2"

# Stop all services
stop: stop-vsock-proxies
    #!/usr/bin/env bash
    echo "🛑 Stopping KeyMeld services..."
    pkill -f keymeld-gateway || true
    pkill -f keymeld-enclave || true
    pkill -f bitcoind || true
    echo "✅ All services stopped"

# Restart all services
restart: stop start

# Check service health
status:
    #!/usr/bin/env bash
    echo "📊 KeyMeld Service Status:"
    echo "=========================="
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
    if command -v curl >/dev/null && curl -s http://localhost:8080/health >/dev/null 2>&1; then
        echo "🌐 Gateway Health Check: ✅ Healthy"
        curl -s http://localhost:8080/health | head -5
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

# Run parallel stress tests
stress mode count amount="50000":
    @echo "🚀 Running KeyMeld stress test..."
    @nix develop -c ./scripts/run-stress-test.sh {{mode}} {{count}} {{amount}}



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
            -port=18444 -fallbackfee=0.0001 -mintxfee=0.00001
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

# Enter development shell
dev:
    @echo "🚀 Entering Nix development shell..."
    nix develop

# ==================================================================================
# Maintenance & Utilities
# ==================================================================================

# Clean all data and rebuild database (works for both quickstart and stress tests)
clean: stop
    #!/usr/bin/env bash
    echo "🧹 Cleaning all KeyMeld data..."

    # Ensure all processes are stopped
    pkill -9 -f keymeld-gateway 2>/dev/null || true
    pkill -9 -f keymeld-enclave 2>/dev/null || true
    pkill -9 -f keymeld_demo 2>/dev/null || true
    sleep 1

    # Remove all data, logs, and build artifacts
    rm -rf data logs target/debug/keymeld-* result
    rm -rf /tmp/keymeld-stress-test

    # Recreate necessary directories
    mkdir -p data logs

    # Clean up Bitcoin stress test wallets if Bitcoin is running
    nix develop -c bash -c '
        if pgrep -f bitcoind >/dev/null && bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 getblockchaininfo >/dev/null 2>&1; then
            echo "🏦 Cleaning Bitcoin stress test wallets..."
            for wallet in $(bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 listwallets 2>/dev/null | grep stress_test || true); do
                bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 unloadwallet "$(echo $wallet | tr -d '\'',\"'\'')" 2>/dev/null || true
            done
        fi
    ' 2>/dev/null || true

    echo "✅ Complete clean finished - ready for quickstart or stress tests"

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
        echo "  Status: ✅ Running on http://localhost:8080"
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
