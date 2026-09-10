#!/usr/bin/env bash
# Source this helper only from explicit local simulation launchers.

keymeld_setup_development_auth() {
    local keymeld_repo_root="${1:?Repository path is required}"
    local keymeld_gateway_binary="${2:?Gateway binary path is required}"
    local keymeld_credential_dir keymeld_temporary_dir

    if [[ "${KEYMELD_ENVIRONMENT:-development}" != development ]]; then
        echo "Local simulation authentication cannot run in a production environment." >&2
        return 1
    fi
    if [[ "${KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES:-true}" != true ]]; then
        echo "This launcher requires explicit local simulation with unattested enclaves." >&2
        return 1
    fi
    if [[ ! -x "$keymeld_gateway_binary" ]]; then
        echo "Build keymeld-gateway before starting local services." >&2
        return 1
    fi

    export KEYMELD_ENVIRONMENT=development
    export KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES=true
    export KEYMELD_GATEWAY_SIGNING_KEY_FILE="${KEYMELD_GATEWAY_SIGNING_KEY_FILE:-$keymeld_repo_root/data/development-channel.key}"
    keymeld_credential_dir="$(dirname -- "$KEYMELD_GATEWAY_SIGNING_KEY_FILE")"
    mkdir -p -- "$keymeld_credential_dir"

    if [[ ! -e "$KEYMELD_GATEWAY_SIGNING_KEY_FILE" ]]; then
        keymeld_temporary_dir="$(mktemp -d "$keymeld_credential_dir/.channel-key.XXXXXX")"
        if ! "$keymeld_gateway_binary" --generate-channel-key "$keymeld_temporary_dir/key" >/dev/null; then
            rm -f -- "$keymeld_temporary_dir/key"
            rmdir -- "$keymeld_temporary_dir"
            return 1
        fi
        # Publish a complete key atomically. Concurrent launchers reuse the winner.
        if ! ln -- "$keymeld_temporary_dir/key" "$KEYMELD_GATEWAY_SIGNING_KEY_FILE" 2>/dev/null; then
            if [[ ! -f "$KEYMELD_GATEWAY_SIGNING_KEY_FILE" ]]; then
                rm -f -- "$keymeld_temporary_dir/key"
                rmdir -- "$keymeld_temporary_dir"
                return 1
            fi
        fi
        rm -f -- "$keymeld_temporary_dir/key"
        rmdir -- "$keymeld_temporary_dir"
    fi
    if [[ ! -f "$KEYMELD_GATEWAY_SIGNING_KEY_FILE" || -L "$KEYMELD_GATEWAY_SIGNING_KEY_FILE" ]]; then
        echo "The local channel credential must be a regular file, not a symbolic link." >&2
        return 1
    fi
    chmod 600 -- "$KEYMELD_GATEWAY_SIGNING_KEY_FILE"
    ENCLAVE_GATEWAY_PUBLIC_KEY="$("$keymeld_gateway_binary" --channel-public-key "$KEYMELD_GATEWAY_SIGNING_KEY_FILE")" || return 1
    export ENCLAVE_GATEWAY_PUBLIC_KEY
    export ENCLAVE_KMS_KEY_ID="${ENCLAVE_KMS_KEY_ID:-alias/keymeld-enclave-master-key}"
    export ENCLAVE_KMS_ENDPOINT="${ENCLAVE_KMS_ENDPOINT:-http://127.0.0.1:4566}"
    echo "Local simulation: channel authentication enabled; Nitro attestation explicitly disabled."
}
