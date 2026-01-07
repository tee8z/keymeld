#!/usr/bin/env bash
# Setup sudoers rule for VSock kernel modules
# This allows loading VSock modules without password prompts

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

QUIET=${QUIET:-false}

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

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    log_error "Don't run this script as root. It will ask for sudo when needed."
    exit 1
fi

# Check if running from justfile (automated context) or CI
# Also treat QUIET=true as automated run to avoid password prompts
AUTOMATED_RUN=${AUTOMATED_RUN:-false}
if [[ "${BASH_SOURCE[0]}" =~ "justfile" ]] || [[ -n "${JUST_INVOCATION_DIRECTORY:-}" ]] || [[ "${CI:-false}" == "true" ]] || [[ -n "${GITHUB_ACTIONS:-}" ]] || [[ -n "${GITLAB_CI:-}" ]] || [[ "${QUIET:-false}" == "true" ]]; then
    AUTOMATED_RUN=true
fi

# Function to check if sudo works without password for modprobe
can_modprobe_passwordless() {
    local test_modules=("vhost_vsock" "vmw_vsock_loopback" "vsock" "vsock_loopback")
    for module in "${test_modules[@]}"; do
        if sudo -n modprobe --dry-run "$module" >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}

SUDOERS_FILE="/etc/sudoers.d/keymeld-vsock"
CURRENT_USER=$(whoami)

log_info "Setting up VSock kernel module permissions for user: $CURRENT_USER"

# Create sudoers rule content
SUDOERS_CONTENT="# Allow $CURRENT_USER to load VSock kernel modules without password
# This is needed for KeyMeld enclave development with VSock simulation
$CURRENT_USER ALL=(root) NOPASSWD: /sbin/modprobe vhost_vsock
$CURRENT_USER ALL=(root) NOPASSWD: /sbin/modprobe vmw_vsock_loopback
$CURRENT_USER ALL=(root) NOPASSWD: /sbin/modprobe vsock
$CURRENT_USER ALL=(root) NOPASSWD: /sbin/modprobe vsock_loopback
$CURRENT_USER ALL=(root) NOPASSWD: /usr/sbin/modprobe vhost_vsock
$CURRENT_USER ALL=(root) NOPASSWD: /usr/sbin/modprobe vmw_vsock_loopback
$CURRENT_USER ALL=(root) NOPASSWD: /usr/sbin/modprobe vsock
$CURRENT_USER ALL=(root) NOPASSWD: /usr/sbin/modprobe vsock_loopback"

# Function to validate sudoers content
validate_sudoers() {
    echo "$SUDOERS_CONTENT" | sudo visudo -c -f - >/dev/null 2>&1
}

# Check if passwordless sudo already works - if so, skip sudoers setup
if can_modprobe_passwordless; then
    if [[ "$QUIET" == "true" ]]; then
        log_quiet "✅ VSock kernel module permissions already configured"
    else
        log_success "✅ Passwordless sudo for VSock modules already works - no setup needed!"
    fi
    exit 0
fi

# In automated mode, only proceed if we have passwordless sudo
# Check this early to avoid any password prompts
if [[ "$AUTOMATED_RUN" == "true" ]]; then
    if ! sudo -n true 2>/dev/null; then
        log_warn "⚠️  Passwordless sudo not available (this is OK, will use fallback mode)"
        exit 0
    fi
fi

# Check if sudoers file exists
if [[ -f "$SUDOERS_FILE" ]]; then
    if [[ "$AUTOMATED_RUN" == "true" ]]; then
        if [[ "$QUIET" != "true" ]]; then
            log_info "Sudoers file exists, ensuring VSock rules are correct..."
        fi
        # In automated mode, always proceed with update to ensure correctness
    else
        log_info "Existing sudoers file found, checking VSock configuration..."
        # In interactive mode, assume it might need updating
        read -p "Do you want to update VSock sudoers rules? [Y/n]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            log_info "Skipping sudoers update"
            exit 0
        fi
    fi
fi

# Validate the sudoers content before writing
log_info "Validating sudoers syntax..."
if ! validate_sudoers; then
    log_error "Generated sudoers content has syntax errors!"
    exit 1
fi

if [[ "$QUIET" != "true" ]]; then
    log_success "Sudoers syntax is valid"
fi

# Create/update the sudoers rule
if [[ "$QUIET" != "true" ]]; then
    log_info "Creating sudoers rule at $SUDOERS_FILE..."
fi

# Try to create the sudoers rule, but handle CI environments gracefully
if ! echo "$SUDOERS_CONTENT" | sudo tee "$SUDOERS_FILE" >/dev/null 2>&1; then
    if [[ "$AUTOMATED_RUN" == "true" ]]; then
        log_warn "⚠️  Could not create sudoers file in CI environment (this is OK, will use fallback mode)"
        exit 0
    else
        log_error "Failed to create sudoers file. Check permissions."
        exit 1
    fi
fi

# Set proper permissions
if ! sudo chmod 440 "$SUDOERS_FILE" 2>/dev/null; then
    if [[ "$AUTOMATED_RUN" == "true" ]]; then
        log_warn "⚠️  Could not set sudoers file permissions in CI environment (this is OK)"
    else
        log_error "Failed to set sudoers file permissions."
        exit 1
    fi
fi

if [[ "$QUIET" != "true" ]]; then
    log_success "VSock sudoers rule created successfully!"
fi

# Test the configuration
if [[ "$QUIET" != "true" ]]; then
    log_info "Testing the new configuration..."
fi

# Test each module loading command
MODULES=("vhost_vsock" "vmw_vsock_loopback" "vsock" "vsock_loopback")
for module in "${MODULES[@]}"; do
    if [[ "$QUIET" != "true" ]]; then
        log_info "Testing: sudo modprobe $module"
    fi
    if sudo -n modprobe "$module" 2>/dev/null; then
        if [[ "$QUIET" != "true" ]]; then
            log_success "✅ $module: Password-free loading works"
        fi
    else
        # Check if module is already loaded
        if lsmod | grep -q "^$module "; then
            if [[ "$QUIET" != "true" ]]; then
                log_info "ℹ️  $module: Already loaded"
            fi
        else
            if [[ "$QUIET" != "true" ]]; then
                log_warn "⚠️  $module: Not available on this system (this is OK)"
            fi
        fi
    fi
done

if [[ "$QUIET" == "true" ]]; then
    log_quiet "✅ VSock kernel module permissions configured"
elif [[ "$AUTOMATED_RUN" == "true" ]]; then
    echo ""
    log_success "🎉 VSock setup complete! No more password prompts needed."
else
    echo ""
    log_success "🎉 VSock sudoers setup complete!"
    echo ""
    log_info "What was configured:"
    echo "  ✅ Password-free modprobe for VSock kernel modules"
    echo "  ✅ Applied to user: $CURRENT_USER"
    echo "  ✅ Sudoers file: $SUDOERS_FILE"
    echo ""
    log_info "You can now run 'nix develop' without password prompts for VSock!"
fi

# Show available VSock devices
if [[ "$QUIET" != "true" ]]; then
    echo ""
    log_info "VSock device status:"
    if [[ -e /dev/vsock ]]; then
        log_success "✅ /dev/vsock is available"
        ls -la /dev/vsock 2>/dev/null || true
    else
        log_warn "⚠️  /dev/vsock not found (will use TCP fallback mode)"
    fi

    if [[ "$AUTOMATED_RUN" != "true" ]]; then
        echo ""
        log_info "Next steps:"
        echo "  1. Run 'nix develop' - no more password prompts!"
        echo "  2. Use 'just quickstart' to test the full setup"
        echo "  3. If you need to remove this later: sudo rm $SUDOERS_FILE"
    fi
fi
