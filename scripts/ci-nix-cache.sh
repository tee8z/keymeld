#!/usr/bin/env bash
# Release workflow helper: keep the Nix outputs a job built, so a later run of
# the same derivations substitutes them instead of building again.
#
#   ci-nix-cache.sh save <cache-dir> <installable>...
#
# Replaces <cache-dir> with a file binary cache holding every output in the
# installables' build closure that the public Nix cache does not sign: what
# this runner built, and what it substituted from an earlier copy of this
# cache. Rust dependency builds, vendored crates and source trees are left out:
# they are large, and the dependency builds change with every version bump.
#
# The release workflow saves the directory to the GitHub Actions cache only
# from pushes to master, and lists it as a trusted substituter on later runs.
# Nix substitutes by store path, so a restored cache can only supply the exact
# outputs a derivation names; it cannot change what a derivation builds.
set -euo pipefail

usage() { echo "usage: $0 save <cache-dir> <installable>..." >&2; exit 2; }
[[ $# -ge 3 && $1 == save ]] || usage
cache_dir=$2
shift 2
[[ $cache_dir == /* ]] || { echo "cache directory must be absolute" >&2; exit 2; }

mapfile -t derivations < <(nix path-info --derivation "$@")
mapfile -t candidates < <(
  nix-store --query --requisites --include-outputs "${derivations[@]}" \
    | grep -v '\.drv$' \
    | grep -Ev -- '-(source|vendor-registry|vendor-cargo-deps|nix-shell-env)$|/[a-z0-9]{32}-(cargo-src|cargo-package)-|-deps-[0-9][^/]*$' \
    | while read -r path; do [[ -e $path ]] && printf '%s\n' "$path"; done
)
[[ ${#candidates[@]} -gt 0 ]] || { echo "nothing to keep" >&2; exit 0; }

# Newer Nix prints an object keyed by store path, older Nix an array.
mapfile -t keep < <(
  nix path-info --json "${candidates[@]}" | jq -r '
    (if type == "array" then .[] else (to_entries[] | .value + {path: .key}) end)
    | select(any(.signatures[]?; startswith("cache.nixos.org-1:")) | not)
    | .path'
)
[[ ${#keep[@]} -gt 0 ]] || { echo "nothing to keep" >&2; exit 0; }

rm -rf -- "$cache_dir"
# Only the selected paths: their references come from the public cache.
nix copy --no-recursive --to "file://$cache_dir?compression=zstd" "${keep[@]}"
echo "Kept ${#keep[@]} store paths ($(du -sh "$cache_dir" | cut -f1)):"
nix path-info --size --human-readable "${keep[@]}" | sort -k2 -h
