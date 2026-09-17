#!/usr/bin/env bash
# Start the gateway with the operator's reviewed production topology.
set -euo pipefail
(( $# <= 1 )) || { echo "Usage: $0 [gateway-binary]" >&2; exit 2; }
keymeld_gateway_binary="${1:-keymeld-gateway}"
keymeld_environment_file="${KEYMELD_AWS_ENV_FILE:-keymeld-aws.env}"
# An explicit invocation override takes precedence over the deployment default.
keymeld_config_override="${CONFIG_PATH:-}"

if [[ -f "$keymeld_environment_file" ]]; then
    echo "Loading AWS environment configuration from $keymeld_environment_file"
    # shellcheck disable=SC1090 # Operator-selected deployment output.
    source "$keymeld_environment_file"
elif [[ -n "${KEYMELD_AWS_ENV_FILE:-}" ]]; then
    echo "Deployment environment file does not exist: $keymeld_environment_file" >&2
    exit 1
else
    echo "No deployment environment file found; using the provided configuration and CID overrides."
fi

export CONFIG_PATH="${keymeld_config_override:-${CONFIG_PATH:-config/production.yaml}}"
export KEYMELD_ENVIRONMENT=production
export RUST_LOG="${RUST_LOG:-info,keymeld_gateway=debug}"
echo "Starting KeyMeld Gateway for AWS Nitro Enclaves with $CONFIG_PATH"
# The gateway validates every configured enclave and its authenticated identity.
exec "$keymeld_gateway_binary"
