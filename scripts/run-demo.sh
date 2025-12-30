#!/usr/bin/env bash
# Run KeyMeld demo (plain or adaptor)
set -euo pipefail

MODE=${1:-plain}
AMOUNT=${2:-50000}
DEST=${3:-bcrt1qf0p0zqynlcq7c4j6vm53qaxapm3chufwfgge80}

if [[ "$MODE" != "plain" && "$MODE" != "adaptor" ]]; then
    echo "❌ Error: mode must be 'plain' or 'adaptor'"
    exit 1
fi

echo "🎮 Running KeyMeld ${MODE} demo..."
LD_LIBRARY_PATH=${CMAKE_LIBRARY_PATH:-} \
    cargo run --bin keymeld_demo -- ${MODE} --config config/example-nix.yaml --amount ${AMOUNT} --destination ${DEST}
