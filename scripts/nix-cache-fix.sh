#!/usr/bin/env bash
# KeyMeld Nix Cache Fix Script
# Resolves SQLite eval cache conflicts that can occur during parallel builds

set -euo pipefail

echo "🔧 KeyMeld Nix Cache Fix"
echo "========================"

# Function to safely remove eval cache
clear_eval_cache() {
    local cache_dir="$HOME/.cache/nix/eval-cache-v6"

    if [ -d "$cache_dir" ]; then
        echo "🧹 Clearing Nix eval cache at: $cache_dir"
        rm -rf "$cache_dir"
        echo "✅ Eval cache cleared"
    else
        echo "ℹ️  No eval cache found (already clean)"
    fi
}

# Function to check for busy SQLite databases
check_busy_databases() {
    local cache_dir="$HOME/.cache/nix/eval-cache-v6"

    if [ -d "$cache_dir" ]; then
        local busy_dbs=$(find "$cache_dir" -name "*.sqlite" -exec lsof {} \; 2>/dev/null | wc -l || echo "0")
        if [ "$busy_dbs" -gt 0 ]; then
            echo "⚠️  Found $busy_dbs busy SQLite database(s)"
            return 1
        fi
    fi
    return 0
}

# Function to kill stuck nix processes
kill_stuck_nix_processes() {
    echo "🔍 Checking for stuck nix processes..."

    local nix_processes=$(pgrep -f "nix.*eval" || echo "")
    if [ -n "$nix_processes" ]; then
        echo "🚫 Found stuck nix evaluation processes: $nix_processes"
        echo "   Killing stuck processes..."
        pkill -f "nix.*eval" || true
        sleep 2
        echo "✅ Stuck processes cleared"
    else
        echo "✅ No stuck nix processes found"
    fi
}

# Function to restart nix daemon if needed
restart_nix_daemon() {
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet nix-daemon 2>/dev/null; then
            echo "🔄 Restarting nix-daemon (systemd)..."
            sudo systemctl restart nix-daemon
            echo "✅ Nix daemon restarted"
        fi
    elif command -v launchctl >/dev/null 2>&1; then
        if launchctl list | grep -q org.nixos.nix-daemon 2>/dev/null; then
            echo "🔄 Restarting nix-daemon (launchd)..."
            sudo launchctl stop org.nixos.nix-daemon || true
            sleep 1
            sudo launchctl start org.nixos.nix-daemon || true
            echo "✅ Nix daemon restarted"
        fi
    else
        echo "ℹ️  Cannot restart nix-daemon (no systemctl or launchctl found)"
    fi
}

# Main execution
main() {
    local fix_level="${1:-basic}"

    case "$fix_level" in
        "basic")
            echo "Running basic cache cleanup..."
            clear_eval_cache
            ;;
        "full")
            echo "Running full cleanup and restart..."
            kill_stuck_nix_processes
            clear_eval_cache
            restart_nix_daemon
            ;;
        "check")
            echo "Checking for issues..."
            if check_busy_databases; then
                echo "✅ No busy databases detected"
                exit 0
            else
                echo "❌ Busy databases detected"
                echo "Run '$0 basic' or '$0 full' to fix"
                exit 1
            fi
            ;;
        *)
            echo "Usage: $0 [basic|full|check]"
            echo ""
            echo "Options:"
            echo "  basic - Clear eval cache only (default)"
            echo "  full  - Clear cache, kill stuck processes, restart daemon"
            echo "  check - Check for issues without fixing"
            echo ""
            echo "Examples:"
            echo "  $0           # Basic cleanup"
            echo "  $0 full      # Full cleanup and restart"
            echo "  $0 check     # Just check for problems"
            exit 1
            ;;
    esac

    echo ""
    echo "🎉 Cache fix completed! You can now run:"
    echo "   just start"
    echo "   just quickstart"
    echo "   nix develop"
}

# Execute main function with all arguments
main "$@"
