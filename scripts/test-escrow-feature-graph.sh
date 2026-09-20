#!/usr/bin/env bash
# Check generic authorization and optional SDK utility boundaries without compilation.
set -euo pipefail
export CARGO_INCREMENTAL=0
escrow_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$escrow_root"

dependency_graph() {
  cargo tree --locked -p "$1" --no-default-features --features "$2" --edges normal --prefix none --format '{p}'
}
requires() {
  if ! grep -Eq "^$1 v" <<< "$graph"; then
    echo "Missing required $1 dependency for $case_name" >&2; exit 1
  fi
}
excludes() {
  if grep -Eq "^($1) v" <<< "$graph"; then
    echo "Unexpected optional dependency ($1) for $case_name" >&2; exit 1
  fi
}
for package in keymeld-core keymeld-sdk; do
  case_name="$package generic escrow"
  graph="$(dependency_graph "$package" escrow)"
  excludes 'dlctix|lightning-invoice|tokio|tokio-vsock|reqwest'
done
case_name='SDK DLC utilities'
graph="$(dependency_graph keymeld-sdk dlctix)"
requires dlctix
excludes 'lightning-invoice|tokio|tokio-vsock|reqwest'
printf '%s\n' 'Generic escrow and optional SDK DLC utility dependency boundaries passed.'
