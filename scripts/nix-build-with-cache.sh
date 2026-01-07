#!/usr/bin/env bash
set -euo pipefail

# nix-build-with-cache.sh
# Optimized build script that leverages Rust cache in Nix environments
# Usage: ./scripts/nix-build-with-cache.sh [target] [--release]

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CACHE_DIR="${HOME}/.cache/keymeld"
BUILD_MODE="debug"
TARGET=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --release)
            BUILD_MODE="release"
            shift
            ;;
        --target)
            TARGET="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--release] [--target TARGET]"
            echo "  --release    Build in release mode"
            echo "  --target     Specify build target"
            echo "  --help       Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Change to project directory
cd "$PROJECT_ROOT"

# Create cache directories
log_info "Setting up cache directories..."
mkdir -p "$CACHE_DIR"/{cargo,target,nix}
mkdir -p "$HOME/.cargo"/{registry,git}

# Set up environment variables for cache-friendly builds
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-1}"
export CARGO_NET_RETRY="${CARGO_NET_RETRY:-3}"
export RUST_LOG="${RUST_LOG:-info}"

# Nix-specific optimizations
export NIX_CONFIG="
eval-cache = false
keep-outputs = true
keep-derivations = true
max-jobs = auto
cores = 0
"

# Check if we're in a Nix environment
if [[ -n "${IN_NIX_SHELL:-}" ]]; then
    log_info "Running in Nix shell environment"
else
    log_info "Not in Nix shell, will use 'nix develop'"
    NIX_CMD="nix develop -c"
fi

# Function to check cache status
check_cache_status() {
    log_info "Checking cache status..."

    if [[ -d "$CARGO_HOME/registry/cache" ]]; then
        local cache_size=$(du -sh "$CARGO_HOME/registry/cache" 2>/dev/null | cut -f1 || echo "0")
        log_info "Cargo registry cache: $cache_size"
    else
        log_warn "No cargo registry cache found"
    fi

    if [[ -d "$CARGO_TARGET_DIR" ]]; then
        local target_size=$(du -sh "$CARGO_TARGET_DIR" 2>/dev/null | cut -f1 || echo "0")
        log_info "Build target cache: $target_size"
    else
        log_warn "No build target cache found"
    fi
}

# Function to optimize cargo cache
optimize_cache() {
    log_info "Optimizing cargo cache..."

    # Clean old cache entries (older than 30 days)
    if command -v find >/dev/null 2>&1; then
        find "$CARGO_HOME/registry/cache" -type f -mtime +30 -delete 2>/dev/null || true
        find "$CARGO_HOME/git/db" -type f -mtime +30 -delete 2>/dev/null || true
    fi

    # Create cargo config for optimized builds
    mkdir -p .cargo
    cat > .cargo/config.toml.cache << 'EOF'
[build]
incremental = true
pipelining = true

[net]
git-fetch-with-cli = true
check-revs = false
retry = 3

[http]
multiplexing = true
timeout = 60

[env]
CARGO_INCREMENTAL = { value = "1", force = false }
CARGO_NET_RETRY = { value = "3", force = false }
EOF

    # Merge with existing config if it exists
    if [[ -f .cargo/config.toml ]]; then
        log_info "Merging with existing cargo config..."
        # Backup original config
        cp .cargo/config.toml .cargo/config.toml.backup
    else
        # Use our optimized config
        mv .cargo/config.toml.cache .cargo/config.toml.temp
    fi
}

# Function to build with cache awareness
build_with_cache() {
    local build_args=()

    if [[ "$BUILD_MODE" == "release" ]]; then
        build_args+=("--release")
        log_info "Building in release mode..."
    else
        log_info "Building in debug mode..."
    fi

    if [[ -n "$TARGET" ]]; then
        build_args+=("--target" "$TARGET")
        log_info "Building for target: $TARGET"
    fi

    # First, try to fetch dependencies if we have network
    log_info "Fetching dependencies..."
    if [[ -n "${NIX_CMD:-}" ]]; then
        $NIX_CMD cargo fetch --locked || log_warn "Failed to fetch dependencies, continuing..."
    else
        cargo fetch --locked || log_warn "Failed to fetch dependencies, continuing..."
    fi

    # Build workspace dependencies first (these cache well)
    log_info "Building workspace dependencies..."
    if [[ -n "${NIX_CMD:-}" ]]; then
        $NIX_CMD cargo build --workspace --locked "${build_args[@]}" || {
            log_error "Failed to build workspace dependencies"
            return 1
        }
    else
        cargo build --workspace --locked "${build_args[@]}" || {
            log_error "Failed to build workspace dependencies"
            return 1
        }
    fi

    log_success "Build completed successfully"
}

# Function to run tests with cache
test_with_cache() {
    log_info "Running tests with cache..."

    if [[ -n "${NIX_CMD:-}" ]]; then
        $NIX_CMD cargo test --workspace --locked || {
            log_error "Tests failed"
            return 1
        }
    else
        cargo test --workspace --locked || {
            log_error "Tests failed"
            return 1
        }
    fi

    log_success "Tests completed successfully"
}

# Function to cleanup temporary files
cleanup() {
    # Restore original cargo config if we backed it up
    if [[ -f .cargo/config.toml.backup ]]; then
        mv .cargo/config.toml.backup .cargo/config.toml
    fi

    # Clean up temporary files
    rm -f .cargo/config.toml.cache .cargo/config.toml.temp
}

# Set up trap for cleanup
trap cleanup EXIT

# Main execution
main() {
    log_info "Starting cache-aware Nix build..."
    log_info "Build mode: $BUILD_MODE"
    log_info "Project root: $PROJECT_ROOT"
    log_info "Cache directory: $CACHE_DIR"

    check_cache_status
    optimize_cache
    build_with_cache

    # Run tests if this is a debug build
    if [[ "$BUILD_MODE" == "debug" ]]; then
        test_with_cache
    fi

    check_cache_status
    log_success "Cache-aware build completed successfully!"
}

# Run main function
main "$@"
