#!/usr/bin/env bash
# Wrapper to run cargo binaries within nix develop environment
# This ensures dynamically linked libraries are available

set -e

BINARY="$1"
shift

exec nix develop --command cargo run --bin "$BINARY" -- "$@"
