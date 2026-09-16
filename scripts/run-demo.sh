#!/usr/bin/env bash
# Run a KeyMeld demo against the explicit local simulation.
set -euo pipefail

keymeld_repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd -- "$keymeld_repo_root"
source "$keymeld_repo_root/scripts/development-auth.sh"
keymeld_setup_development_environment

MODE=${1:-plain}
AMOUNT=${2:-50000}
DEST=${3:-bcrt1qf0p0zqynlcq7c4j6vm53qaxapm3chufwfgge80}

demo_arguments=("$MODE" --config config/example-nix.yaml)
case "$MODE" in
    plain|adaptor) demo_arguments+=(--amount "$AMOUNT" --destination "$DEST") ;;
    single-signer|dlctix) ;;
    *) echo "Error: mode must be plain, adaptor, single-signer, or dlctix" >&2; exit 1 ;;
esac

echo "Running KeyMeld ${MODE} demo..."
if [ -n "${SKIP_BUILD:-}" ] && [ -f "target/debug/keymeld_demo" ]; then
    LD_LIBRARY_PATH=${CMAKE_LIBRARY_PATH:-} \
        ./target/debug/keymeld_demo "${demo_arguments[@]}"
else
    LD_LIBRARY_PATH=${CMAKE_LIBRARY_PATH:-} \
        cargo run --bin keymeld_demo -- "${demo_arguments[@]}"
fi
