#!/usr/bin/env bash
set -euo pipefail

echo "CI/CD: Building KeyMeld Enclave EIF for AWS Nitro"

# Configuration
EIF_NAME="${EIF_NAME:-keymeld-enclave}"
VERSION="${VERSION:-$(git rev-parse --short HEAD 2>/dev/null || echo 'latest')}"
ENCLAVE_ID="${ENCLAVE_ID:-0}"
OUTPUT_FILE="${OUTPUT_FILE:-$EIF_NAME-$ENCLAVE_ID-$VERSION.eif}"

# Generic authorization support is part of the measured image.
KEYMELD_ESCROW_VARIANT="${KEYMELD_ESCROW_VARIANT:-none}"
case "$KEYMELD_ESCROW_VARIANT" in
  none) image_suffix=; cargo_features= ;;
  escrow) image_suffix=-escrow; cargo_features=escrow ;;
  *) echo "KEYMELD_ESCROW_VARIANT must be none or escrow" >&2; exit 1 ;;
esac
base_image="keymeld-enclave$image_suffix:latest"

# Check prerequisites
if ! command -v nitro-cli &> /dev/null; then
  echo "nitro-cli not found. Install AWS Nitro CLI first:"
  echo "   https://docs.aws.amazon.com/enclaves/latest/user/nitro-cli-install.html"
  exit 1
fi

echo "Build Configuration:"
echo "   EIF Name: $EIF_NAME"
echo "   Version: $VERSION"
echo "   Output: $OUTPUT_FILE"
echo "   Compiled escrow variant: $KEYMELD_ESCROW_VARIANT"

# These public settings become part of the measured enclave image.
: "${ENCLAVE_GATEWAY_PUBLIC_KEY:?Set the provisioned gateway verification key}"
: "${ENCLAVE_KMS_KEY_ID:?Set the KMS key allowed for this enclave}"
: "${AWS_REGION:?Set the enclave AWS region}"
ENCLAVE_KMS_ENDPOINT="${ENCLAVE_KMS_ENDPOINT:-aws-kms}"
[[ "$ENCLAVE_GATEWAY_PUBLIC_KEY" =~ ^(02|03)[0-9a-fA-F]{64}$ ]] || { echo "Invalid gateway public key" >&2; exit 1; }
[[ "$ENCLAVE_ID" =~ ^(0|[1-9][0-9]{0,9})$ ]] && (( ENCLAVE_ID <= 4294967295 )) || { echo "Invalid enclave ID" >&2; exit 1; }
[[ ! -e "$OUTPUT_FILE" && ! -e "$OUTPUT_FILE.manifest.json" ]] || { echo "Refusing to overwrite an EIF artifact" >&2; exit 1; }
command -v jq >/dev/null
signing_args=()
if [[ -n "${EIF_SIGNING_KEY:-}" || -n "${EIF_SIGNING_CERTIFICATE:-}" ]]; then
  : "${EIF_SIGNING_KEY:?Set the EIF signing key path or KMS ARN}"
  : "${EIF_SIGNING_CERTIFICATE:?Set the matching EIF signing certificate path}"
  signing_args=(--private-key "$EIF_SIGNING_KEY" --signing-certificate "$EIF_SIGNING_CERTIFICATE")
fi
provisioned_image="$EIF_NAME-$ENCLAVE_ID:$VERSION"

# Include the Nix runtime closure; copying only the binary breaks its loader.
build_context=$(mktemp -d -t keymeld-eif.XXXXXXXX)
trap 'rm -rf -- "$build_context"' EXIT
nix build ".#docker-enclave$image_suffix" --out-link "$build_context/base-image"
docker load < "$build_context/base-image"
cat > "$build_context/Dockerfile" <<'EOF'
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG ENCLAVE_GATEWAY_PUBLIC_KEY
ARG ENCLAVE_KMS_KEY_ID
ARG ENCLAVE_KMS_ENDPOINT
ARG ENCLAVE_ID
ARG AWS_REGION
ENV ENCLAVE_GATEWAY_PUBLIC_KEY=$ENCLAVE_GATEWAY_PUBLIC_KEY
ENV ENCLAVE_KMS_KEY_ID=$ENCLAVE_KMS_KEY_ID
ENV ENCLAVE_KMS_ENDPOINT=$ENCLAVE_KMS_ENDPOINT
ENV ENCLAVE_ID=$ENCLAVE_ID
ENV AWS_REGION=$AWS_REGION
ENV KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES=false
ENV TRANSPORT_MODE=vsock
EOF
docker build -t "$provisioned_image" \
  --build-arg BASE_IMAGE="$base_image" \
  --build-arg ENCLAVE_GATEWAY_PUBLIC_KEY="$ENCLAVE_GATEWAY_PUBLIC_KEY" \
  --build-arg ENCLAVE_KMS_KEY_ID="$ENCLAVE_KMS_KEY_ID" \
  --build-arg ENCLAVE_KMS_ENDPOINT="$ENCLAVE_KMS_ENDPOINT" \
  --build-arg ENCLAVE_ID="$ENCLAVE_ID" --build-arg AWS_REGION="$AWS_REGION" \
  "$build_context"

# Signing credentials are supplied only to Nitro CLI, never to Docker.
echo "Converting provisioned enclave image to EIF..."
nitro-cli build-enclave --docker-uri "$provisioned_image" \
  --output-file "$OUTPUT_FILE" "${signing_args[@]}"
nitro-cli describe-eif --eif-path "$OUTPUT_FILE" > "$build_context/measurements.json"
jq -e '.Measurements | [.PCR0, .PCR1, .PCR2] | all(.[];
  type == "string" and test("^[0-9a-fA-F]{96}$") and test("[1-9a-fA-F]"))' \
  "$build_context/measurements.json" >/dev/null
artifact_hash=$(sha256sum -- "$OUTPUT_FILE")
source_dirty=false
[[ -z "$(git status --porcelain --untracked-files=no)" ]] || source_dirty=true
jq -n --argjson enclave_id "$ENCLAVE_ID" --arg eif_path "$OUTPUT_FILE" \
  --arg sha256 "${artifact_hash%% *}" \
  --arg version "$VERSION" --arg source_commit "$(git rev-parse HEAD)" \
  --argjson source_dirty "$source_dirty" \
  --arg escrow_variant "$KEYMELD_ESCROW_VARIANT" \
  --arg cargo_features "$cargo_features" \
  --arg kms_key_arn "$ENCLAVE_KMS_KEY_ID" --arg kms_endpoint "$ENCLAVE_KMS_ENDPOINT" \
  --arg aws_region "$AWS_REGION" --arg gateway_public_key "$ENCLAVE_GATEWAY_PUBLIC_KEY" \
  --slurpfile description "$build_context/measurements.json" \
  '{enclave_id: $enclave_id, eif_path: $eif_path, sha256: $sha256,
    version: $version, source_commit: $source_commit, source_dirty: $source_dirty,
    escrow_variant: $escrow_variant,
    cargo_features: (if $cargo_features == "" then [] else ($cargo_features | split(",")) end),
    kms_key_arn: $kms_key_arn, kms_endpoint: $kms_endpoint,
    aws_region: $aws_region, gateway_public_key: $gateway_public_key,
    pcr0: $description[0].Measurements.PCR0,
    pcr1: $description[0].Measurements.PCR1,
    pcr2: $description[0].Measurements.PCR2,
    pcr8: ($description[0].Measurements.PCR8 // null)}' > "$OUTPUT_FILE.manifest.json"
echo "Built $OUTPUT_FILE and $OUTPUT_FILE.manifest.json. Review the measurements before publishing."
# This build helper does not publish artifacts or move mutable aliases.
docker rmi "$provisioned_image" 2>/dev/null || true
