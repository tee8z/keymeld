#!/usr/bin/env bash
# VSock setup script with intelligent fallback modes
# Handles kernel module loading gracefully without password prompts when possible

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROXY_DIR="/tmp/keymeld-vsock-proxies"
VSOCK_DEVICE="/dev/vsock"
MODULES=("vhost_vsock" "vmw_vsock_loopback" "vsock" "vsock_loopback")
QUIET=${QUIET:-false}

# Logging functions
log_info() {
    if [[ "$QUIET" != "true" ]]; then
        echo -e "${BLUE}[INFO]${NC} $1"
    fi
}

log_success() {
    if [[ "$QUIET" != "true" ]]; then
        echo -e "${GREEN}[SUCCESS]${NC} $1"
    fi
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Quiet logging - only for essential messages
log_quiet() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if running in CI environment
# Default to true to avoid password prompts in dev environment
is_ci() {
    [[ "${CI:-true}" == "true" ]] || [[ -n "${GITHUB_ACTIONS:-}" ]] || [[ -n "${GITLAB_CI:-}" ]]
}

# Check if we can load modules without password
can_load_modules_passwordless() {
    # Try to load a module without password
    sudo -n modprobe --dry-run vhost_vsock >/dev/null 2>&1
}

# Try to load a kernel module with fallbacks
try_load_module() {
    local module="$1"
    local loaded=false

    # Check if module is already loaded
    if lsmod | grep -q "^$module "; then
        if [[ "$QUIET" != "true" ]]; then
            log_info "✅ $module: Already loaded"
        fi
        return 0
    fi

    # Try loading as root first
    if [[ $EUID -eq 0 ]]; then
        if modprobe "$module" 2>/dev/null; then
            log_success "✅ $module: Loaded as root"
            loaded=true
        fi
    else
        # Try passwordless sudo first
        if sudo -n modprobe "$module" 2>/dev/null; then
            if [[ "$QUIET" != "true" ]]; then
                log_success "✅ $module: Loaded with passwordless sudo"
            fi
            loaded=true
        elif can_load_modules_passwordless; then
            # We have passwordless sudo for modprobe
            if sudo modprobe "$module" 2>/dev/null; then
                if [[ "$QUIET" != "true" ]]; then
                    log_success "✅ $module: Loaded with sudo"
                fi
                loaded=true
            fi
        elif ! is_ci; then
            # In interactive mode, ask for password
            log_warn "🔑 $module: Requires password (run 'scripts/setup-vsock-sudoers.sh' to fix this)"
            if sudo modprobe "$module" 2>/dev/null; then
                if [[ "$QUIET" != "true" ]]; then
                    log_success "✅ $module: Loaded with password"
                fi
                loaded=true
            fi
        fi
    fi

    if ! $loaded; then
        log_warn "⚠️  $module: Not available or failed to load (will use fallback mode)"
        return 1
    fi

    return 0
}

# Load VSock kernel modules
load_vsock_modules() {
    if [[ "$QUIET" != "true" ]]; then
        log_info "Loading VSock kernel modules..."
    fi

    local modules_loaded=0
    for module in "${MODULES[@]}"; do
        if try_load_module "$module"; then
            ((modules_loaded++))
        fi
    done

    if [[ $modules_loaded -gt 0 ]]; then
        if [[ "$QUIET" != "true" ]]; then
            log_success "Loaded $modules_loaded VSock modules"
        fi
        return 0
    else
        log_warn "No VSock modules loaded - will use TCP fallback"
        return 1
    fi
}

# Check VSock availability
check_vsock_available() {
    if [[ -e "$VSOCK_DEVICE" ]]; then
        if [[ "$QUIET" != "true" ]]; then
            log_success "✅ VSock device available at $VSOCK_DEVICE"
            ls -la "$VSOCK_DEVICE" 2>/dev/null || true
        fi
        return 0
    else
        log_warn "⚠️  VSock device not found at $VSOCK_DEVICE"
        return 1
    fi
}

# Start VSock proxy services
start_vsock_proxies() {
    mkdir -p "$PROXY_DIR"

    if check_vsock_available; then
        if [[ "$QUIET" != "true" ]]; then
            log_info "Starting VSock-to-TCP proxies..."
        fi

        for i in {0..2}; do
            local vsock_port=$((5000 + i))
            local cid=2  # Host CID for local VSock simulation
            local tcp_port=$((9000 + i))

            if [[ "$QUIET" != "true" ]]; then
                log_info "Starting VSock proxy $i: VSock CID:$cid:$vsock_port → TCP:$tcp_port"
            fi

            # Kill any existing proxy on this port
            pkill -f "TCP-LISTEN:$tcp_port" 2>/dev/null || true

            # Start the proxy
            socat TCP-LISTEN:$tcp_port,reuseaddr,fork VSOCK-CONNECT:$cid:$vsock_port \
                > "$PROXY_DIR/vsock-proxy-$i.log" 2>&1 &
            echo $! > "$PROXY_DIR/vsock-proxy-$i.pid"

            if [[ "$QUIET" != "true" ]]; then
                log_success "✅ VSock proxy $i started (PID: $!)"
            fi
        done

        if [[ "$QUIET" == "true" ]]; then
            log_quiet "🎉 VSock setup complete with hardware VSock!"
        else
            log_success "🎉 All VSock proxies started"
            echo "   Access enclaves via:"
            echo "   - Enclave 0: localhost:9000 → VSock CID:2:5000"
            echo "   - Enclave 1: localhost:9001 → VSock CID:2:5001"
            echo "   - Enclave 2: localhost:9002 → VSock CID:2:5002"
        fi

        return 0
    else
        return 1
    fi
}

# Start TCP fallback proxies
start_tcp_fallback_proxies() {
    mkdir -p "$PROXY_DIR"

    log_info "Starting TCP-to-TCP fallback proxies..."

    for i in {0..2}; do
        local vsock_port=$((5000 + i))
        local tcp_port=$((9000 + i))

        log_info "Starting TCP proxy $i: TCP:$vsock_port → TCP:$tcp_port"

        # Kill any existing proxy on this port
        pkill -f "TCP-LISTEN:$tcp_port" 2>/dev/null || true

        # Start the proxy
        socat TCP-LISTEN:$tcp_port,reuseaddr,fork TCP:localhost:$vsock_port \
            > "$PROXY_DIR/tcp-proxy-$i.log" 2>&1 &
        echo $! > "$PROXY_DIR/tcp-proxy-$i.pid"

        log_success "✅ TCP proxy $i started (PID: $!)"
    done

    log_success "🎉 All TCP fallback proxies started"
    echo "   Access enclaves via:"
    echo "   - Enclave 0: localhost:9000 → localhost:5000"
    echo "   - Enclave 1: localhost:9001 → localhost:5001"
    echo "   - Enclave 2: localhost:9002 → localhost:5002"
}

# Stop all proxy services
stop_proxies() {
    log_info "Stopping all proxy services..."

    if [[ -d "$PROXY_DIR" ]]; then
        local stopped=0

        for pidfile in "$PROXY_DIR"/*.pid; do
            if [[ -f "$pidfile" ]]; then
                local pid=$(cat "$pidfile")
                if kill "$pid" 2>/dev/null; then
                    log_success "✅ Stopped proxy (PID: $pid)"
                    ((stopped++))
                fi
                rm -f "$pidfile"
            fi
        done

        # Clean up log files
        rm -f "$PROXY_DIR"/*.log

        if [[ $stopped -gt 0 ]]; then
            log_success "Stopped $stopped proxy services"
        else
            log_info "No running proxy services found"
        fi

        # Remove proxy directory if empty
        rmdir "$PROXY_DIR" 2>/dev/null || true
    else
        log_info "No proxy services found"
    fi
}

# Show status of proxy services
show_status() {
    echo "📊 VSock Proxy Status:"
    echo ""

    # Check VSock availability
    if check_vsock_available; then
        echo "VSock Mode: ✅ Hardware VSock available"
    else
        echo "VSock Mode: ⚠️  TCP fallback mode"
    fi

    echo ""
    echo "Proxy Services:"

    if [[ -d "$PROXY_DIR" ]]; then
        local running=0

        for i in {0..2}; do
            local pidfile="$PROXY_DIR/vsock-proxy-$i.pid"
            local tcp_pidfile="$PROXY_DIR/tcp-proxy-$i.pid"

            if [[ -f "$pidfile" ]]; then
                local pid=$(cat "$pidfile" 2>/dev/null)
                if kill -0 "$pid" 2>/dev/null; then
                    echo "  ✅ VSock Proxy $i (PID: $pid) - localhost:$((9000 + i))"
                    ((running++))
                else
                    echo "  ❌ VSock Proxy $i (dead)"
                fi
            elif [[ -f "$tcp_pidfile" ]]; then
                local pid=$(cat "$tcp_pidfile" 2>/dev/null)
                if kill -0 "$pid" 2>/dev/null; then
                    echo "  ✅ TCP Proxy $i (PID: $pid) - localhost:$((9000 + i))"
                    ((running++))
                else
                    echo "  ❌ TCP Proxy $i (dead)"
                fi
            else
                echo "  ⚪ Proxy $i: Not running"
            fi
        done

        echo ""
        echo "Total running: $running/3"
    else
        echo "  ⚪ No proxy services configured"
    fi
}

# Setup VSock with intelligent fallbacks
setup_vsock() {
    if [[ "$QUIET" != "true" ]]; then
        log_info "🔧 Setting up VSock for KeyMeld enclave simulation..."
    fi

    # Try to load kernel modules
    if load_vsock_modules; then
        # Modules loaded, try VSock proxies
        if start_vsock_proxies; then
            if [[ "$QUIET" != "true" ]]; then
                log_success "🎉 VSock setup complete with hardware VSock!"
            fi
            return 0
        fi
    fi

    # Fallback to TCP mode
    log_warn "🔄 Falling back to TCP-only mode..."
    start_tcp_fallback_proxies
    if [[ "$QUIET" == "true" ]]; then
        log_quiet "🎉 VSock setup complete with TCP fallback mode!"
    else
        log_success "🎉 VSock setup complete with TCP fallback mode!"
    fi
}

# Show help
show_help() {
    echo "Usage: $0 {setup|start|stop|status|help}"
    echo ""
    echo "Commands:"
    echo "  setup   - Set up VSock with intelligent fallbacks (default)"
    echo "  start   - Start proxy services (alias for setup)"
    echo "  stop    - Stop all proxy services"
    echo "  status  - Show status of proxy services"
    echo "  help    - Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  CI            - Set to 'true' to run in CI mode (no password prompts)"
    echo "  QUIET         - Set to 'true' to reduce output verbosity"
    echo "  GITHUB_ACTIONS - Automatically detected GitHub Actions environment"
    echo ""
    echo "Tips:"
    echo "  - Run 'scripts/setup-vsock-sudoers.sh' to enable password-free module loading"
    echo "  - VSock will automatically fallback to TCP mode if hardware VSock is unavailable"
    echo "  - In CI environments, password prompts are automatically skipped"
    echo "  - Use QUIET=true for minimal output during automated runs"
}

# Main command handling
case "${1:-setup}" in
    setup|start)
        setup_vsock
        ;;
    stop)
        stop_proxies
        ;;
    status)
        show_status
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
