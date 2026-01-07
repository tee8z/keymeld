{
  description = "KeyMeld - Production-ready distributed MuSig2 Bitcoin signing system for AWS Nitro Enclaves";

  # Note: This flake includes SQLite eval cache conflict prevention.
  # If you encounter "SQLite database is busy" errors, run: just fix-cache

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane = {
      url = "github:ipetkov/crane";
    };

  };

  # Disable eval cache to prevent SQLite busy issues during parallel builds
  # This resolves "SQLite database is busy" errors that can occur when
  # multiple Nix processes access the eval cache simultaneously
  nixConfig = {
    eval-cache = false;
    extra-substituters = [
      "https://cache.nixos.org/"
    ];
    extra-trusted-public-keys = [
      "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
    ];
    allow-import-from-derivation = true;
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Use specific Rust version for reproducible builds
        rustToolchain = pkgs.rust-bin.stable."1.88.0".default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Common environment variables
        commonEnvs = {
          SQLX_OFFLINE = "true";
          RUST_LOG = "info";
          # Enable incremental compilation for faster rebuilds
          CARGO_INCREMENTAL = "1";
        };

        # System dependencies that all services need
        commonDeps = with pkgs; [
          pkg-config
          openssl
          cmake
          protobuf
          sqlite
          curl
          jq
        ];

        # Build workspace dependencies once (shared across all crates)
        # Use fixed hash to improve caching and avoid eval conflicts
        workspaceDeps = craneLib.buildDepsOnly {
          pname = "keymeld-workspace-deps";
          version = "0.1.0";
          src = craneLib.path ./.;
          buildInputs = commonDeps;
          nativeBuildInputs = commonDeps;
          # Allow substitutes for faster dependency downloads from cache
          preferLocalBuild = false;
          allowSubstitutes = true;
        };

        # Filter source for each crate to only include relevant files
        gatewaySrc = pkgs.lib.cleanSourceWith {
          src = craneLib.path ./.;
          filter = path: type:
            (craneLib.filterCargoSources path type) ||
            (builtins.match ".*crates/keymeld-gateway/.*" path != null) ||
            (builtins.match ".*crates/keymeld-core/.*" path != null) ||
            (builtins.match ".*\\.sqlx/.*" path != null) ||
            (builtins.match ".*config/.*" path != null);
        };

        enclaveSrc = pkgs.lib.cleanSourceWith {
          src = craneLib.path ./.;
          filter = path: type:
            (craneLib.filterCargoSources path type) ||
            (builtins.match ".*crates/keymeld-enclave/.*" path != null) ||
            (builtins.match ".*crates/keymeld-core/.*" path != null);
        };

        demoSrc = pkgs.lib.cleanSourceWith {
          src = craneLib.path ./.;
          filter = path: type:
            (craneLib.filterCargoSources path type) ||
            (builtins.match ".*examples/.*" path != null) ||
            (builtins.match ".*crates/keymeld-core/.*" path != null) ||
            (builtins.match ".*\\.sqlx/.*" path != null) ||
            (builtins.match ".*config/.*" path != null);
        };

        # Individual service builds with filtered sources
        keymeld-gateway = craneLib.buildPackage {
          pname = "keymeld-gateway";
          version = "0.1.0";
          src = gatewaySrc;
          cargoArtifacts = workspaceDeps;
          buildInputs = commonDeps;
          nativeBuildInputs = commonDeps;
          cargoExtraArgs = "--bin keymeld-gateway";

          # Allow parallel builds and caching for speed
          preferLocalBuild = false;
          allowSubstitutes = true;

          # Copy required files for runtime
          postInstall = ''
            mkdir -p $out/share/keymeld-gateway
            cp -r crates/keymeld-gateway/migrations $out/share/keymeld-gateway/
            cp -r config $out/share/keymeld-gateway/
          '';
        } // commonEnvs;

        keymeld-enclave = craneLib.buildPackage {
          pname = "keymeld-enclave";
          version = "0.1.0";
          src = enclaveSrc;
          cargoArtifacts = workspaceDeps;
          buildInputs = commonDeps;
          nativeBuildInputs = commonDeps;
          cargoExtraArgs = "--bin keymeld-enclave";

          # Allow parallel builds and caching for speed
          preferLocalBuild = false;
          allowSubstitutes = true;
        } // commonEnvs;

        keymeld-demo = craneLib.buildPackage {
          pname = "keymeld-demo";
          version = "0.1.0";
          src = demoSrc;
          cargoArtifacts = workspaceDeps;
          buildInputs = commonDeps;
          nativeBuildInputs = commonDeps;
          cargoExtraArgs = "--bin keymeld_demo";

          # Allow parallel builds and caching for speed
          preferLocalBuild = false;
          allowSubstitutes = true;

          postInstall = ''
            mkdir -p $out/share/keymeld-demo
            cp -r config $out/share/keymeld-demo/
          '';
        } // commonEnvs;

        # SQLean UUID extension for SQLite (optional for now)
        # TODO: Add proper SQLean extension when needed
        # sqlean-uuid = pkgs.stdenv.mkDerivation rec {
        #   pname = "sqlean-uuid";
        #   version = "latest";
        #   # Will be implemented when exact hash is determined
        # };

        # Development shell with all tools
        devShell = pkgs.mkShell {
          buildInputs = commonDeps ++ [
            rustToolchain
            pkgs.just
            pkgs.sqlx-cli
            pkgs.bitcoin
            pkgs.bitcoind
            pkgs.socat
            pkgs.iproute2
            pkgs.util-linux
            pkgs.netcat
            pkgs.procps
            moto-env
            pkgs.awscli2
            pkgs.litestream
            pkgs.haproxy
            self.packages.${system}.vsock-proxy
            self.packages.${system}.bitcoin-rpc-proxy
          ];

          shellHook = ''
            # Clear any problematic eval cache on shell entry to prevent SQLite conflicts
            if [ -d "$HOME/.cache/nix/eval-cache-v6" ]; then
              rm -rf "$HOME/.cache/nix/eval-cache-v6" 2>/dev/null || true
            fi

            # Setup VSock loopback for local development (non-blocking)
            # This allows enclaves to communicate via VSock without actual AWS Nitro hardware
            if [ "$(id -u)" = "0" ]; then
              # Running as root - try to load kernel modules quietly
              modprobe vhost_vsock 2>/dev/null || true
              modprobe vmw_vsock_loopback 2>/dev/null || true
              modprobe vsock 2>/dev/null || true
            fi

            # Only show welcome message if this is an interactive shell
            if [ -t 1 ] && [ -z "$KEYMELD_QUIET_SHELL" ]; then
              echo "🚀 KeyMeld Development Environment (Rust ${rustToolchain.version})"
              echo "Use 'just help' to see available commands"
              if [ -e /dev/vsock ]; then
                echo "✅ VSock available for enclave simulation"
              fi
            fi
          '';

          inherit (commonEnvs) SQLX_OFFLINE RUST_LOG;
        };

        # VSock setup script for local development
        setup-vsock = pkgs.writeShellScriptBin "setup-vsock" ''
          #!/usr/bin/env bash

          echo "🔧 Setting up VSock for KeyMeld enclave simulation..."

          # Function to try loading a module
          try_load_module() {
            local module=$1
            echo "Attempting to load $module..."
            if [ "$(id -u)" = "0" ]; then
              modprobe "$module" 2>/dev/null && echo "✅ $module loaded" || echo "⚠️  $module not available"
            else
              sudo modprobe "$module" 2>/dev/null && echo "✅ $module loaded" || echo "⚠️  $module not available"
            fi
          }

          # Try to load VSock kernel modules (don't fail if unavailable)
          echo "Loading VSock kernel modules..."
          try_load_module "vhost_vsock"
          try_load_module "vmw_vsock_loopback"
          try_load_module "vsock"
          try_load_module "vsock_loopback"

          # Create VSock proxy directories
          mkdir -p /tmp/keymeld-vsock-proxies

          # Check if VSock is available
          if [ -e /dev/vsock ]; then
            echo "✅ /dev/vsock device is available"
            ls -la /dev/vsock 2>/dev/null || true
            echo "🎉 VSock setup complete! Starting VSock proxy services..."

            # Start VSock proxy services for each enclave
            for i in {0..2}; do
              port=$((5000 + i))
              cid=2
              proxy_port=$((9000 + i))

              echo "Starting VSock proxy for enclave $i (CID:$cid, VSock:$port → TCP:$proxy_port)"
              socat TCP-LISTEN:$proxy_port,reuseaddr,fork VSOCK-CONNECT:$cid:$port > /tmp/keymeld-vsock-proxies/proxy-$i.log 2>&1 &
              echo $! > /tmp/keymeld-vsock-proxies/proxy-$i.pid
            done

            echo "✅ VSock proxy services started"
            echo "   Enclave 0: localhost:9000 → VSock CID:2 port:5000"
            echo "   Enclave 1: localhost:9001 → VSock CID:2 port:5001"
            echo "   Enclave 2: localhost:9002 → VSock CID:2 port:5002"
          else
            echo "⚠️  /dev/vsock device not found"
            echo "Setting up TCP-only fallback mode..."

            # Create TCP-to-TCP proxy as fallback
            for i in {0..2}; do
              vsock_port=$((5000 + i))
              proxy_port=$((9000 + i))

              echo "Starting TCP proxy for enclave $i (TCP:$vsock_port → TCP:$proxy_port)"
              socat TCP-LISTEN:$proxy_port,reuseaddr,fork TCP:localhost:$vsock_port > /tmp/keymeld-vsock-proxies/proxy-$i.log 2>&1 &
              echo $! > /tmp/keymeld-vsock-proxies/proxy-$i.pid
            done

            echo "✅ TCP fallback proxy services started"
          fi
        '';

        # VSock proxy management script
        vsock-proxy = pkgs.writeShellScriptBin "vsock-proxy" ''
          #!/usr/bin/env bash
          PROXY_DIR="/tmp/keymeld-vsock-proxies"

          case "''${1:-start}" in
            start)
              echo "🚀 Starting VSock proxy services..."

              # Load VSock kernel modules
              echo "Loading VSock kernel modules..."
              modprobe vhost_vsock 2>/dev/null || sudo modprobe vhost_vsock 2>/dev/null || echo "⚠️  vhost_vsock not available"
              modprobe vsock_loopback 2>/dev/null || sudo modprobe vsock_loopback 2>/dev/null || echo "⚠️  vsock_loopback not available"
              modprobe vsock 2>/dev/null || sudo modprobe vsock 2>/dev/null || echo "⚠️  vsock not available"

              # Create VSock proxy directories
              mkdir -p "$PROXY_DIR"

              # Check if VSock is available and start appropriate proxies
              if [ -e /dev/vsock ]; then
                echo "✅ VSock device available - starting VSock proxies"

                # Start VSock proxy services for each enclave
                for i in {0..2}; do
                  port=$((5000 + i))
                  cid=2
                  proxy_port=$((9000 + i))

                  echo "Starting VSock proxy for enclave $i (CID:$cid, VSock:$port → TCP:$proxy_port)"
                  socat TCP-LISTEN:$proxy_port,reuseaddr,fork VSOCK-CONNECT:$cid:$port > "$PROXY_DIR/proxy-$i.log" 2>&1 &
                  echo $! > "$PROXY_DIR/proxy-$i.pid"
                done

                echo "✅ VSock proxy services started"
                echo "   Enclave 0: localhost:9000 → VSock CID:2 port:5000"
                echo "   Enclave 1: localhost:9001 → VSock CID:2 port:5001"
                echo "   Enclave 2: localhost:9002 → VSock CID:2 port:5002"
              else
                echo "⚠️  VSock device not found - starting TCP fallback proxies"

                # Create TCP-to-TCP proxy as fallback
                for i in {0..2}; do
                  vsock_port=$((5000 + i))
                  proxy_port=$((9000 + i))

                  echo "Starting TCP proxy for enclave $i (TCP:$vsock_port → TCP:$proxy_port)"
                  socat TCP-LISTEN:$proxy_port,reuseaddr,fork TCP:localhost:$vsock_port > "$PROXY_DIR/proxy-$i.log" 2>&1 &
                  echo $! > "$PROXY_DIR/proxy-$i.pid"
                done

                echo "✅ TCP fallback proxy services started"
              fi
              ;;
            stop)
              echo "🛑 Stopping VSock proxy services..."
              if [ -d "$PROXY_DIR" ]; then
                for pidfile in "$PROXY_DIR"/*.pid; do
                  if [ -f "$pidfile" ]; then
                    pid=$(cat "$pidfile")
                    kill "$pid" 2>/dev/null && echo "Stopped proxy (PID: $pid)" || echo "Proxy $pid already stopped"
                    rm -f "$pidfile"
                  fi
                done
                rm -f "$PROXY_DIR"/*.log
                echo "✅ All VSock proxy services stopped"
              else
                echo "No proxy services found"
              fi
              ;;
            status)
              echo "📊 VSock Proxy Status:"
              if [ -d "$PROXY_DIR" ]; then
                for i in {0..2}; do
                  pidfile="$PROXY_DIR/proxy-$i.pid"
                  if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
                    echo "  Proxy $i: ✅ Running (PID: $(cat "$pidfile"))"
                  else
                    echo "  Proxy $i: ❌ Not running"
                  fi
                done
              else
                echo "  No proxy services configured"
              fi
              ;;
            *)
              echo "Usage: vsock-proxy {start|stop|status}"
              exit 1
              ;;
          esac
        '';

        # Bitcoin RPC proxy using HAProxy for connection pooling and rate limiting
        # This prevents overwhelming bitcoind with too many concurrent RPC requests
        bitcoin-rpc-proxy = pkgs.writeShellScriptBin "bitcoin-rpc-proxy" ''
          #!/usr/bin/env bash
          PROXY_DIR="/tmp/keymeld-bitcoin-proxy"
          HAPROXY_CFG="$PROXY_DIR/haproxy.cfg"
          HAPROXY_PID="$PROXY_DIR/haproxy.pid"
          PROXY_PORT="''${BITCOIN_PROXY_PORT:-18550}"
          BACKEND_PORT="''${BITCOIN_RPC_PORT:-18443}"
          MAX_CONN="''${BITCOIN_MAX_CONN:-50}"
          QUEUE_TIMEOUT="''${BITCOIN_QUEUE_TIMEOUT:-60s}"

          case "''${1:-start}" in
            start)
              echo "🚀 Starting Bitcoin RPC proxy (HAProxy)..."
              echo "   Proxy port: $PROXY_PORT → Backend: 127.0.0.1:$BACKEND_PORT"
              echo "   Max concurrent connections to bitcoind: $MAX_CONN"
              echo "   Queue timeout: $QUEUE_TIMEOUT"

              # Check if already running
              if [ -f "$HAPROXY_PID" ] && kill -0 "$(cat "$HAPROXY_PID")" 2>/dev/null; then
                echo "⚠️  Bitcoin RPC proxy already running (PID: $(cat "$HAPROXY_PID"))"
                exit 0
              fi

              mkdir -p "$PROXY_DIR"

              # Generate HAProxy configuration
              cat > "$HAPROXY_CFG" <<EOF
global
    daemon
    maxconn 4096
    pidfile $HAPROXY_PID
    log stdout format raw local0 info

defaults
    mode http
    timeout connect 10s
    timeout client 120s
    timeout server 120s
    timeout queue $QUEUE_TIMEOUT
    option httplog
    log global

frontend bitcoin_rpc_frontend
    bind 127.0.0.1:$PROXY_PORT
    default_backend bitcoin_rpc_backend

backend bitcoin_rpc_backend
    # Queue excess connections instead of rejecting them
    # This is key for handling burst traffic from parallel tests
    server bitcoind 127.0.0.1:$BACKEND_PORT maxconn $MAX_CONN check inter 5s

    # Health check to ensure bitcoind is responsive (HAProxy 2.2+ syntax)
    option httpchk
    http-check send meth POST uri / ver HTTP/1.1 hdr Content-Type application/json hdr Authorization "Basic a2V5bWVsZDprZXltZWxkcGFzczEyMw==" body "{\"method\":\"getblockchaininfo\",\"params\":[],\"id\":1}"
    http-check expect status 200

# Stats interface for monitoring (optional)
listen stats
    bind 127.0.0.1:18480
    mode http
    stats enable
    stats uri /
    stats refresh 5s
EOF

              echo "📋 HAProxy configuration written to $HAPROXY_CFG"

              # Start HAProxy
              ${pkgs.haproxy}/bin/haproxy -f "$HAPROXY_CFG"

              sleep 1
              if [ -f "$HAPROXY_PID" ] && kill -0 "$(cat "$HAPROXY_PID")" 2>/dev/null; then
                echo "✅ Bitcoin RPC proxy started (PID: $(cat "$HAPROXY_PID"))"
                echo ""
                echo "📊 Usage:"
                echo "   Bitcoin RPC via proxy: http://127.0.0.1:$PROXY_PORT"
                echo "   Stats dashboard: http://127.0.0.1:18480"
                echo ""
                echo "   Update your Bitcoin RPC URL to use port $PROXY_PORT instead of $BACKEND_PORT"
              else
                echo "❌ Failed to start HAProxy"
                cat "$PROXY_DIR/haproxy.log" 2>/dev/null || true
                exit 1
              fi
              ;;
            stop)
              echo "🛑 Stopping Bitcoin RPC proxy..."
              if [ -f "$HAPROXY_PID" ]; then
                pid=$(cat "$HAPROXY_PID")
                kill "$pid" 2>/dev/null && echo "✅ Stopped HAProxy (PID: $pid)" || echo "HAProxy already stopped"
                rm -f "$HAPROXY_PID"
              else
                echo "No HAProxy running"
              fi
              ;;
            status)
              echo "📊 Bitcoin RPC Proxy Status:"
              if [ -f "$HAPROXY_PID" ] && kill -0 "$(cat "$HAPROXY_PID")" 2>/dev/null; then
                echo "  HAProxy: ✅ Running (PID: $(cat "$HAPROXY_PID"))"
                echo "  Proxy port: $PROXY_PORT → Backend: $BACKEND_PORT"
                echo "  Stats: http://127.0.0.1:18480"

                # Show queue stats if available
                if command -v curl &>/dev/null; then
                  echo ""
                  echo "  Current stats:"
                  curl -s "http://127.0.0.1:18480/;csv" 2>/dev/null | grep bitcoind | awk -F',' '{print "    Queue: "$18", Current conn: "$5"/"$6", Total: "$8}' || true
                fi
              else
                echo "  HAProxy: ❌ Not running"
              fi
              ;;
            reload)
              echo "🔄 Reloading Bitcoin RPC proxy configuration..."
              if [ -f "$HAPROXY_PID" ]; then
                ${pkgs.haproxy}/bin/haproxy -f "$HAPROXY_CFG" -sf "$(cat "$HAPROXY_PID")"
                echo "✅ Configuration reloaded"
              else
                echo "HAProxy not running, starting..."
                $0 start
              fi
              ;;
            *)
              echo "Usage: bitcoin-rpc-proxy {start|stop|status|reload}"
              echo ""
              echo "Environment variables:"
              echo "  BITCOIN_PROXY_PORT  - Port for proxy to listen on (default: 18444)"
              echo "  BITCOIN_RPC_PORT    - Backend bitcoind RPC port (default: 18443)"
              echo "  BITCOIN_MAX_CONN    - Max concurrent connections to bitcoind (default: 50)"
              echo "  BITCOIN_QUEUE_TIMEOUT - How long to queue requests (default: 60s)"
              exit 1
              ;;
          esac
        '';

        # Simple script that just ensures bitcoind is available
        start-bitcoin = pkgs.writeShellScriptBin "start-bitcoin" ''
          echo "Bitcoin Core available via: ${pkgs.bitcoind}/bin/bitcoind"
          echo "Bitcoin CLI available via: ${pkgs.bitcoin}/bin/bitcoin-cli"
        '';

        # Script to stop Bitcoin Core
        stop-bitcoin = pkgs.writeShellScriptBin "stop-bitcoin" ''
          set -e
          BITCOIN_DATA_DIR=''${BITCOIN_DATA_DIR:-$PWD/data/bitcoin}

          if [ -f "$BITCOIN_DATA_DIR/bitcoind.pid" ]; then
            PID=$(cat "$BITCOIN_DATA_DIR/bitcoind.pid")
            echo "Stopping Bitcoin Core (PID: $PID)..."
            kill $PID || true
            rm -f "$BITCOIN_DATA_DIR/bitcoind.pid"
            echo "Bitcoin Core stopped"
          else
            echo "Bitcoin Core not running"
          fi
        '';

        # Python environment with moto and server dependencies
        moto-env = pkgs.python3.withPackages (ps: with ps; [
          moto
          flask
          flask-cors
          werkzeug
          boto3
        ]);

        # Script to run moto-server (AWS mock) with KMS
        run-localstack = pkgs.writeShellScriptBin "run-localstack" ''
          set -e
          export LOCALSTACK_HOST=''${LOCALSTACK_HOST:-"127.0.0.1"}
          export MOTO_PORT=''${MOTO_PORT:-"4566"}
          export DATA_DIR=''${DATA_DIR:-"$PWD/data/localstack"}
          export AWS_DEFAULT_REGION=''${AWS_DEFAULT_REGION:-"us-west-2"}
          export AWS_ACCESS_KEY_ID=''${AWS_ACCESS_KEY_ID:-"test"}
          export AWS_SECRET_ACCESS_KEY=''${AWS_SECRET_ACCESS_KEY:-"test"}

          mkdir -p "$DATA_DIR"

          echo "🔐 Starting Moto (AWS mock server) with KMS service..."
          echo "   Host: $LOCALSTACK_HOST:$MOTO_PORT"
          echo "   Services: kms, s3"
          echo "   Region: $AWS_DEFAULT_REGION"
          echo "   Data Directory: $DATA_DIR"
          echo ""
          echo "📋 AWS Endpoint: http://$LOCALSTACK_HOST:$MOTO_PORT"
          echo "   Use with AWS CLI: aws --endpoint-url=http://$LOCALSTACK_HOST:$MOTO_PORT kms ..."
          echo ""

          # Start moto-server with KMS and S3 support
          exec ${moto-env}/bin/moto_server -p $MOTO_PORT
        '';

        # Script to run gateway
        run-gateway = pkgs.writeShellScriptBin "run-gateway" ''
          set -e
          export RUST_LOG=''${RUST_LOG:-"info,keymeld_gateway=debug"}
          export KEYMELD_HOST=''${KEYMELD_HOST:-"127.0.0.1"}
          export KEYMELD_PORT=''${KEYMELD_PORT:-"8080"}
          export KEYMELD_DATABASE_PATH=''${KEYMELD_DATABASE_PATH:-"$PWD/data/keymeld.db"}
          export CONFIG_PATH=''${CONFIG_PATH:-"$PWD/config/development.yaml"}
          export TEST_MODE=''${TEST_MODE:-"true"}
          export ENCLAVE_3_HOST=''${ENCLAVE_3_HOST:-"127.0.0.1"}
          export ENCLAVE_4_HOST=''${ENCLAVE_4_HOST:-"127.0.0.1"}
          export ENCLAVE_5_HOST=''${ENCLAVE_5_HOST:-"127.0.0.1"}

          # Ensure database directory exists
          mkdir -p "$(dirname "$KEYMELD_DATABASE_PATH")"
          mkdir -p "$PWD/logs"

          # Run migrations if database doesn't exist
          if [ ! -f "$KEYMELD_DATABASE_PATH" ]; then
            echo "Creating and migrating database..."
            ${pkgs.sqlx-cli}/bin/sqlx database create --database-url "sqlite:$KEYMELD_DATABASE_PATH"
            cd crates/keymeld-gateway && ${pkgs.sqlx-cli}/bin/sqlx migrate run --database-url "sqlite:../../$KEYMELD_DATABASE_PATH"
            cd ../..
          fi

          echo "Starting KeyMeld Gateway..."
          echo "  Host: $KEYMELD_HOST:$KEYMELD_PORT"
          echo "  Database: $KEYMELD_DATABASE_PATH"
          echo "  Config: $CONFIG_PATH"

          exec ${keymeld-gateway}/bin/keymeld-gateway 2>&1 | tee "$PWD/logs/gateway.log"
        '';

        # Script to run enclave
        run-enclave = pkgs.writeShellScriptBin "run-enclave" ''
          set -e
          export RUST_LOG=''${RUST_LOG:-"info,keymeld_enclave=debug"}
          export VSOCK_PORT=''${VSOCK_PORT:-"5000"}
          export ENCLAVE_ID=''${ENCLAVE_ID:-"0"}
          export TEST_MODE=''${TEST_MODE:-"true"}

          mkdir -p "$PWD/logs"

          echo "Starting KeyMeld Enclave $ENCLAVE_ID on port $VSOCK_PORT..."
          exec ${keymeld-enclave}/bin/keymeld-enclave 2>&1 | tee "$PWD/logs/enclave-$ENCLAVE_ID.log"
        '';

        # Script to run demo
        run-demo = pkgs.writeShellScriptBin "run-demo" ''
          set -e
          export RUST_LOG=''${RUST_LOG:-"info,keymeld_demo=debug"}
          export GATEWAY_URL=''${GATEWAY_URL:-"http://127.0.0.1:8080"}
          export ESPLORA_URL=''${ESPLORA_URL:-"http://127.0.0.1:3002/api"}
          export BITCOIN_NETWORK=''${BITCOIN_NETWORK:-"regtest"}
          export NUM_SIGNERS=''${NUM_SIGNERS:-"2"}
          export KEYMELD_CONFIG_PATH=''${KEYMELD_CONFIG_PATH:-"$PWD/config/example-nix.yaml"}
          export KEYMELD_KEYS_DIR=''${KEYMELD_KEYS_DIR:-"/tmp/keymeld-keys"}
          export BITCOIN_RPC_URL=''${BITCOIN_RPC_URL:-"http://keymeld:keymeldpass123@127.0.0.1:18443"}
          export GATEWAY_URL=''${GATEWAY_URL:-"http://127.0.0.1:8080"}

          mkdir -p "$KEYMELD_KEYS_DIR"
          mkdir -p "$PWD/logs"

          echo "Starting KeyMeld Demo..."
          echo "  Gateway: $GATEWAY_URL"
          echo "  Config: $KEYMELD_CONFIG_PATH"
          echo "  Keys: $KEYMELD_KEYS_DIR"
          echo "  Bitcoin RPC: $BITCOIN_RPC_URL"

          # Wait a moment for Bitcoin RPC to stabilize
          sleep 2

          exec ${keymeld-demo}/bin/keymeld_demo "$@" 2>&1 | tee "$PWD/logs/demo.log"
        '';

        # Simple service runners
        run-services = pkgs.writeShellScriptBin "run-services" ''
          echo "Use individual service commands:"
          echo "  nix run .#gateway"
          echo "  nix run .#enclave"
          echo "  nix run .#bitcoin"
          echo "  nix run .#demo"
        '';

        # Stop all services script
        stop-all-nix = pkgs.writeShellScriptBin "stop-all-nix" ''
          set -e

          echo "🛑 Stopping KeyMeld services..."

          # Stop Litestream if running
          pkill -f litestream || true

          # Stop Bitcoin Core
          ${stop-bitcoin}/bin/stop-bitcoin

          # Kill any remaining KeyMeld processes
          pkill -f keymeld-gateway || true
          pkill -f keymeld-enclave || true
          pkill -f bitcoind || true

          echo "✅ All services stopped"
        '';

        # Script to setup S3 bucket in Moto and start Litestream
        run-litestream = pkgs.writeShellScriptBin "run-litestream" ''
          set -e
          export AWS_ENDPOINT_URL=''${AWS_ENDPOINT_URL:-"http://localhost:4566"}
          export AWS_DEFAULT_REGION=''${AWS_DEFAULT_REGION:-"us-west-2"}
          export AWS_ACCESS_KEY_ID=''${AWS_ACCESS_KEY_ID:-"test"}
          export AWS_SECRET_ACCESS_KEY=''${AWS_SECRET_ACCESS_KEY:-"test"}
          export LITESTREAM_CONFIG=''${LITESTREAM_CONFIG:-"$PWD/config/litestream.yml"}
          export LITESTREAM_S3_BUCKET=''${LITESTREAM_S3_BUCKET:-"keymeld-db-backups"}

          echo "🗄️ Setting up Litestream for SQLite replication..."

          # Check if Moto is running
          if ! pgrep -f moto_server > /dev/null; then
            echo "❌ Moto is not running. Start it first with: just kms start"
            exit 1
          fi

          # Create S3 bucket in Moto if it doesn't exist
          echo "📦 Creating S3 bucket in Moto: $LITESTREAM_S3_BUCKET"
          ${pkgs.awscli2}/bin/aws --endpoint-url=$AWS_ENDPOINT_URL s3 mb s3://$LITESTREAM_S3_BUCKET 2>/dev/null || \
            echo "   Bucket already exists"

          # List buckets to verify
          echo "📋 Available S3 buckets:"
          ${pkgs.awscli2}/bin/aws --endpoint-url=$AWS_ENDPOINT_URL s3 ls

          # Start Litestream
          echo "🚀 Starting Litestream replication..."
          echo "   Config: $LITESTREAM_CONFIG"
          echo "   Database: ./data/keymeld.db"
          echo "   S3 Bucket: s3://$LITESTREAM_S3_BUCKET"
          echo ""

          mkdir -p logs
          exec ${pkgs.litestream}/bin/litestream replicate -config "$LITESTREAM_CONFIG" 2>&1 | tee logs/litestream.log
        '';

        # Script to restore database from Litestream backup
        restore-litestream = pkgs.writeShellScriptBin "restore-litestream" ''
          set -e
          export AWS_ENDPOINT_URL=''${AWS_ENDPOINT_URL:-"http://localhost:4566"}
          export AWS_DEFAULT_REGION=''${AWS_DEFAULT_REGION:-"us-west-2"}
          export AWS_ACCESS_KEY_ID=''${AWS_ACCESS_KEY_ID:-"test"}
          export AWS_SECRET_ACCESS_KEY=''${AWS_SECRET_ACCESS_KEY:-"test"}
          export LITESTREAM_CONFIG=''${LITESTREAM_CONFIG:-"$PWD/config/litestream.yml"}

          echo "📥 Restoring database from Litestream backup..."
          echo "   Config: $LITESTREAM_CONFIG"
          echo "   Target: ./data/keymeld.db"
          echo ""

          # Backup existing database if it exists
          if [ -f "./data/keymeld.db" ]; then
            echo "⚠️  Backing up existing database to ./data/keymeld.db.bak"
            cp ./data/keymeld.db ./data/keymeld.db.bak
          fi

          # Restore from Litestream
          ${pkgs.litestream}/bin/litestream restore -config "$LITESTREAM_CONFIG" -o ./data/keymeld.db ./data/keymeld.db

          echo "✅ Database restored successfully"
        '';

        # CI/CD Pipeline: Build Enclave EIF
        build-enclave-eif = pkgs.writeShellScriptBin "build-enclave-eif" ''
          set -e

          echo "🏗️ CI/CD: Building KeyMeld Enclave EIF for AWS Nitro"

          # Configuration
          EIF_NAME="''${EIF_NAME:-keymeld-enclave}"
          VERSION="''${VERSION:-$(git rev-parse --short HEAD 2>/dev/null || echo 'latest')}"
          OUTPUT_FILE="''${OUTPUT_FILE:-$EIF_NAME-$VERSION.eif}"
          S3_BUCKET="''${S3_BUCKET:-}"

          # Check prerequisites
          if ! command -v nitro-cli &> /dev/null; then
            echo "❌ nitro-cli not found. Install AWS Nitro CLI first:"
            echo "   https://docs.aws.amazon.com/enclaves/latest/user/nitro-cli-install.html"
            exit 1
          fi

          echo "📋 Build Configuration:"
          echo "   EIF Name: $EIF_NAME"
          echo "   Version: $VERSION"
          echo "   Output: $OUTPUT_FILE"
          echo "   S3 Bucket: ''${S3_BUCKET:-not_configured}"

          # Build Nix package first for reproducibility
          echo "📦 Building Nix package..."
          nix build .#keymeld-enclave

          # Create Docker image using Nix result
          echo "🐳 Creating Docker image from Nix build..."
          cat > Dockerfile.eif <<EOF
          FROM amazonlinux:latest
          COPY result/bin/keymeld-enclave /usr/bin/keymeld-enclave
          RUN chmod +x /usr/bin/keymeld-enclave
          ENTRYPOINT ["/usr/bin/keymeld-enclave"]
          EOF

          docker build -t $EIF_NAME:$VERSION -f Dockerfile.eif .

          # Build EIF from Docker image
          echo "🔧 Converting Docker image to EIF..."
          nitro-cli build-enclave \
            --docker-uri $EIF_NAME:$VERSION \
            --output-file "$OUTPUT_FILE"

          echo "✅ Enclave EIF built: $OUTPUT_FILE"
          echo "📊 EIF Metadata:"
          nitro-cli describe-eif --eif-path "$OUTPUT_FILE"

          # Upload to S3 if bucket configured (CI/CD pipeline)
          if [ -n "$S3_BUCKET" ] && command -v aws &> /dev/null; then
            echo "📤 Uploading EIF to S3..."
            aws s3 cp "$OUTPUT_FILE" "s3://$S3_BUCKET/keymeld/eifs/$OUTPUT_FILE"
            echo "✅ EIF uploaded to s3://$S3_BUCKET/keymeld/eifs/$OUTPUT_FILE"

            # Create latest symlink
            aws s3 cp "s3://$S3_BUCKET/keymeld/eifs/$OUTPUT_FILE" "s3://$S3_BUCKET/keymeld/eifs/$EIF_NAME-latest.eif"
            echo "🔗 Latest symlink updated"
          fi

          # Cleanup
          rm -f Dockerfile.eif
          docker rmi $EIF_NAME:$VERSION 2>/dev/null || true
        '';

        # Production: Download EIF and Deploy
        deploy-aws-enclaves = pkgs.writeShellScriptBin "deploy-aws-enclaves" ''
          set -e

          echo "🚀 Production: Deploying KeyMeld to AWS Nitro Enclaves"

          # Configuration
          EIF_NAME="''${EIF_NAME:-keymeld-enclave}"
          VERSION="''${VERSION:-latest}"
          S3_BUCKET="''${S3_BUCKET:-}"
          EIF_PATH="''${EIF_PATH:-$EIF_NAME-$VERSION.eif}"
          ENCLAVE_MEMORY="''${ENCLAVE_MEMORY:-512}"
          ENCLAVE_CPUS="''${ENCLAVE_CPUS:-1}"
          NUM_ENCLAVES="''${NUM_ENCLAVES:-3}"

          # Check prerequisites
          if ! command -v nitro-cli &> /dev/null; then
            echo "❌ nitro-cli not found. Install AWS Nitro CLI first."
            exit 1
          fi

          if ! command -v jq &> /dev/null; then
            echo "❌ jq not found. Please install jq for JSON parsing."
            exit 1
          fi

          echo "📋 Deployment Configuration:"
          echo "   EIF Name: $EIF_NAME"
          echo "   Version: $VERSION"
          echo "   S3 Bucket: ''${S3_BUCKET:-local_file}"
          echo "   Memory: $ENCLAVE_MEMORY MB"
          echo "   CPUs: $ENCLAVE_CPUS"
          echo "   Enclaves: $NUM_ENCLAVES"

          # Download EIF from S3 if configured, otherwise use local
          if [ -n "$S3_BUCKET" ] && command -v aws &> /dev/null; then
            echo "📥 Downloading EIF from S3..."
            aws s3 cp "s3://$S3_BUCKET/keymeld/eifs/$EIF_PATH" "./$EIF_PATH"
            echo "✅ Downloaded: $EIF_PATH"
          elif [ ! -f "$EIF_PATH" ]; then
            echo "❌ EIF not found: $EIF_PATH"
            echo "   Either set S3_BUCKET or provide local EIF file"
            exit 1
          fi

          # Verify EIF
          echo "🔍 Verifying EIF..."
          nitro-cli describe-eif --eif-path "$EIF_PATH"

          # Arrays to store enclave info
          declare -a ENCLAVE_IDS
          declare -a ENCLAVE_CIDS

          # Start enclaves and capture CIDs
          echo "🔧 Starting AWS Nitro Enclaves..."
          for i in $(seq 0 $((NUM_ENCLAVES-1))); do
            echo "Starting enclave $i..."

            # Start enclave with debug output
            ENCLAVE_OUTPUT=$(nitro-cli run-enclave \
              --eif-path "$EIF_PATH" \
              --memory "$ENCLAVE_MEMORY" \
              --cpu-count "$ENCLAVE_CPUS" \
              --enclave-name "keymeld-enclave-$i" \
              --debug-mode 2>/dev/null || nitro-cli run-enclave \
              --eif-path "$EIF_PATH" \
              --memory "$ENCLAVE_MEMORY" \
              --cpu-count "$ENCLAVE_CPUS" \
              --enclave-name "keymeld-enclave-$i")

            # Extract enclave ID
            ENCLAVE_ID=$(echo "$ENCLAVE_OUTPUT" | jq -r '.EnclaveId')
            ENCLAVE_IDS[$i]="$ENCLAVE_ID"

            # Wait and get CID - retry logic for reliability
            echo "   Waiting for enclave to initialize..."
            for attempt in $(seq 1 10); do
              sleep 2
              ENCLAVE_CID=$(nitro-cli describe-enclaves 2>/dev/null | \
                jq -r ".[] | select(.EnclaveId == \"$ENCLAVE_ID\") | .ContextId" 2>/dev/null || echo "")

              if [ -n "$ENCLAVE_CID" ] && [ "$ENCLAVE_CID" != "null" ]; then
                ENCLAVE_CIDS[$i]="$ENCLAVE_CID"
                echo "✅ Enclave $i ready: ID=$ENCLAVE_ID, CID=$ENCLAVE_CID"
                break
              fi

              if [ $attempt -eq 10 ]; then
                echo "❌ Failed to get CID for enclave $i after 10 attempts"
                exit 1
              fi

              echo "   Attempt $attempt: Waiting for CID assignment..."
            done
          done

          # Generate environment configuration
          echo "📝 Generating production environment..."
          cat > keymeld-aws.env <<EOF
# KeyMeld AWS Nitro Enclave Production Configuration
# Generated: $(date)
# Version: $VERSION
# EIF: $EIF_PATH

# Enclave CIDs (dynamically assigned by AWS)
export KEYMELD_ENCLAVE_0_CID=''${ENCLAVE_CIDS[0]}
export KEYMELD_ENCLAVE_1_CID=''${ENCLAVE_CIDS[1]}
export KEYMELD_ENCLAVE_2_CID=''${ENCLAVE_CIDS[2]}

# Production environment
export KEYMELD_ENVIRONMENT=production
export CONFIG_PATH=config/production.yaml

# Deployment metadata
export KEYMELD_VERSION=$VERSION
export KEYMELD_EIF_PATH=$EIF_PATH
export KEYMELD_DEPLOYED_AT=$(date -Iseconds)
EOF

          echo "✅ AWS Nitro Enclaves deployed successfully!"
          echo ""
          echo "📋 Deployment Summary:"
          echo "   Version: $VERSION"
          echo "   EIF: $EIF_PATH"
          for i in $(seq 0 $((NUM_ENCLAVES-1))); do
            echo "   Enclave $i: ID=''${ENCLAVE_IDS[$i]}, CID=''${ENCLAVE_CIDS[$i]}"
          done
          echo ""
          echo "🔧 Next Steps:"
          echo "   1. Source environment: source keymeld-aws.env"
          echo "   2. Start gateway: nix run .#gateway-aws"
          echo "   3. Health check: curl http://localhost:443/health"
          echo ""
          echo "📄 Environment saved: keymeld-aws.env"
        '';

        gateway-aws = pkgs.writeShellScriptBin "gateway-aws" ''
          set -e

          echo "🌐 Starting KeyMeld Gateway for AWS Nitro Enclaves"

          # Check if environment file exists
          if [ -f "keymeld-aws.env" ]; then
            echo "📋 Loading AWS environment configuration..."
            source keymeld-aws.env
          else
            echo "⚠️  No keymeld-aws.env found. Using environment variables directly."
            echo "   Make sure KEYMELD_ENCLAVE_*_CID variables are set."
          fi

          # Verify CIDs are set
          if [ -z "$KEYMELD_ENCLAVE_0_CID" ]; then
            echo "❌ KEYMELD_ENCLAVE_0_CID not set. Run 'nix run .#deploy-aws' first."
            exit 1
          fi

          echo "🔧 Gateway Configuration:"
          echo "   Environment: ''${KEYMELD_ENVIRONMENT:-production}"
          echo "   Config: ''${CONFIG_PATH:-config/production.yaml}"
          echo "   Enclave 0 CID: $KEYMELD_ENCLAVE_0_CID"
          echo "   Enclave 1 CID: ''${KEYMELD_ENCLAVE_1_CID:-not_set}"
          echo "   Enclave 2 CID: ''${KEYMELD_ENCLAVE_2_CID:-not_set}"

          # Start gateway with production configuration
          export RUST_LOG=''${RUST_LOG:-"info,keymeld_gateway=debug"}
          export KEYMELD_ENVIRONMENT=''${KEYMELD_ENVIRONMENT:-production}

          echo "🚀 Starting gateway..."
          ${keymeld-gateway}/bin/keymeld-gateway
        '';

        stop-aws-enclaves = pkgs.writeShellScriptBin "stop-aws-enclaves" ''
          set -e

          echo "🛑 Stopping AWS Nitro Enclaves..."

          if ! command -v nitro-cli &> /dev/null; then
            echo "❌ nitro-cli not found."
            exit 1
          fi

          # Get list of running enclaves
          ENCLAVES=$(nitro-cli describe-enclaves | jq -r '.[].EnclaveId' 2>/dev/null || echo "")

          if [ -z "$ENCLAVES" ]; then
            echo "ℹ️  No running enclaves found."
            exit 0
          fi

          # Stop each enclave
          echo "$ENCLAVES" | while read -r enclave_id; do
            if [ -n "$enclave_id" ]; then
              echo "Stopping enclave: $enclave_id"
              nitro-cli terminate-enclave --enclave-id "$enclave_id"
            fi
          done

          # Clean up environment file
          if [ -f "keymeld-aws.env" ]; then
            echo "🧹 Removing environment file: keymeld-aws.env"
            rm keymeld-aws.env
          fi

          echo "✅ All AWS Nitro Enclaves stopped"
        '';

      in
      {
        # Development shell
        devShells.default = devShell;

        # Individual packages
        packages = {
          default = keymeld-gateway;
          keymeld-gateway = keymeld-gateway;
          keymeld-enclave = keymeld-enclave;
          keymeld-demo = keymeld-demo;

          # Utility scripts
          start-bitcoin = start-bitcoin;
          stop-bitcoin = stop-bitcoin;
          run-services = run-services;
          stop-all-nix = stop-all-nix;
          vsock-proxy = vsock-proxy;
          bitcoin-rpc-proxy = bitcoin-rpc-proxy;

          # Moto (AWS mock server for KMS and S3)
          run-moto = run-localstack;
          run-localstack = run-localstack;  # Alias for backwards compatibility

          # Litestream (SQLite replication)
          run-litestream = run-litestream;
          restore-litestream = restore-litestream;

          # AWS deployment automation
          build-eif = build-enclave-eif;      # CI/CD: Build and upload EIF
          deploy-aws = deploy-aws-enclaves;   # Production: Download and deploy
          gateway-aws = gateway-aws;          # Production: Start gateway
          stop-aws = stop-aws-enclaves;       # Production: Stop and cleanup
        };

        # Apps that can be run with `nix run`
        apps = {
          default = {
            type = "app";
            program = "${keymeld-gateway}/bin/keymeld-gateway";
            meta = {
              description = "KeyMeld Gateway - Main API server for MuSig2 distributed signing";
              mainProgram = "keymeld-gateway";
            };
          };

          gateway = {
            type = "app";
            program = "${run-gateway}/bin/run-gateway";
            meta = {
              description = "Start KeyMeld Gateway with environment setup";
              mainProgram = "run-gateway";
            };
          };

          enclave = {
            type = "app";
            program = "${run-enclave}/bin/run-enclave";
            meta = {
              description = "Start KeyMeld Enclave for secure key operations";
              mainProgram = "run-enclave";
            };
          };

          demo = {
            type = "app";
            program = "${run-demo}/bin/run-demo";
            meta = {
              description = "Run KeyMeld demo with Bitcoin regtest";
              mainProgram = "run-demo";
            };
          };

          start = {
            type = "app";
            program = "${run-services}/bin/run-services";
            meta = {
              description = "Start all KeyMeld services";
              mainProgram = "run-services";
            };
          };

          stop = {
            type = "app";
            program = "${stop-all-nix}/bin/stop-all-nix";
            meta = {
              description = "Stop all KeyMeld services";
              mainProgram = "stop-all-nix";
            };
          };

          bitcoin = {
            type = "app";
            program = "${start-bitcoin}/bin/start-bitcoin";
            meta = {
              description = "Start Bitcoin Core for development";
              mainProgram = "start-bitcoin";
            };
          };

          # Moto (AWS mock server for KMS and S3)
          moto = {
            type = "app";
            program = "${run-localstack}/bin/run-localstack";
            meta = {
              description = "Start Moto with KMS and S3 services for development";
              mainProgram = "run-localstack";
            };
          };

          # Alias for backwards compatibility
          localstack = {
            type = "app";
            program = "${run-localstack}/bin/run-localstack";
            meta = {
              description = "Start Moto with KMS and S3 services for development (alias for moto)";
              mainProgram = "run-localstack";
            };
          };

          # Litestream (SQLite replication)
          litestream = {
            type = "app";
            program = "${run-litestream}/bin/run-litestream";
            meta = {
              description = "Start Litestream to replicate SQLite database to S3";
              mainProgram = "run-litestream";
            };
          };

          restore = {
            type = "app";
            program = "${restore-litestream}/bin/restore-litestream";
            meta = {
              description = "Restore database from Litestream S3 backup";
              mainProgram = "restore-litestream";
            };
          };

          # AWS Nitro Enclave deployment
          build-eif = {
            type = "app";
            program = "${build-enclave-eif}/bin/build-enclave-eif";
            meta = {
              description = "Build Enclave Image Format (EIF) for AWS Nitro";
              mainProgram = "build-enclave-eif";
            };
          };

          deploy-aws = {
            type = "app";
            program = "${deploy-aws-enclaves}/bin/deploy-aws-enclaves";
            meta = {
              description = "Deploy KeyMeld to AWS Nitro Enclaves with dynamic CID discovery";
              mainProgram = "deploy-aws-enclaves";
            };
          };

          gateway-aws = {
            type = "app";
            program = "${gateway-aws}/bin/gateway-aws";
            meta = {
              description = "Start KeyMeld Gateway configured for AWS Nitro Enclaves";
              mainProgram = "gateway-aws";
            };
          };

          stop-aws = {
            type = "app";
            program = "${stop-aws-enclaves}/bin/stop-aws-enclaves";
            meta = {
              description = "Stop all AWS Nitro Enclaves and cleanup";
              mainProgram = "stop-aws-enclaves";
            };
          };
        };

        # Checks for CI
        checks = {
          # Run basic build check
          build = craneLib.cargoClippy ({
            pname = "keymeld-clippy";
            version = "0.1.0";
            src = craneLib.path ./.;
            cargoArtifacts = workspaceDeps;
            buildInputs = commonDeps;
            nativeBuildInputs = commonDeps;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            preferLocalBuild = true;
          } // commonEnvs);

          # Run tests
          test = craneLib.cargoNextest ({
            pname = "keymeld-tests";
            version = "0.1.0";
            src = craneLib.path ./.;
            cargoArtifacts = workspaceDeps;
            buildInputs = commonDeps;
            nativeBuildInputs = commonDeps;
            preferLocalBuild = true;
          } // commonEnvs);

          # Format check
          fmt = craneLib.cargoFmt {
            src = craneLib.cleanCargoSource (craneLib.path ./.);
            preferLocalBuild = true;
          };
        };
      });
}
