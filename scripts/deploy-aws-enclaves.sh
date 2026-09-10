#!/usr/bin/env bash
# Deploy reviewed local EIF artifacts. Each enclave ID has its own measured image.
set -euo pipefail

: "${EIF_MANIFEST:?Set EIF_MANIFEST to the reviewed per-enclave artifact JSON array}"
: "${KEYMELD_ENCLAVE_PCR8:?Pin the approved EIF signing certificate PCR8}"
keymeld_environment_file="${KEYMELD_AWS_ENV_FILE:-keymeld-aws.env}"
keymeld_memory="${ENCLAVE_MEMORY:-512}"
keymeld_cpus="${ENCLAVE_CPUS:-2}"

for command in nitro-cli jq sha256sum; do
    command -v "$command" >/dev/null || { echo "Required command unavailable: $command" >&2; exit 1; }
done
[[ "$KEYMELD_ENCLAVE_PCR8" =~ ^[0-9a-fA-F]{96}$ && "$KEYMELD_ENCLAVE_PCR8" =~ [1-9a-fA-F] ]] || {
    echo "PCR8 must be a nonzero SHA-384 measurement." >&2; exit 1;
}
[[ "$keymeld_memory" =~ ^[0-9]+$ && "$keymeld_cpus" =~ ^[0-9]+$ ]] || {
    echo "Enclave memory and CPU counts must be positive integers." >&2; exit 1;
}
[[ "$keymeld_memory" -ge 64 && "$keymeld_cpus" -ge 1 ]] || exit 1
[[ ! -e "$keymeld_environment_file" && ! -L "$keymeld_environment_file" ]] || {
    echo "Refusing to replace an existing deployment environment file." >&2; exit 1;
}

jq -e '
  type == "array" and length > 0 and
  (map(.enclave_id) | unique | length) == length and
  (map(.sha256) | unique | length) == length and
  all(.[];
    (.enclave_id | type == "number" and floor == . and . >= 0 and . <= 4294967295) and
    (.eif_path | type == "string" and length > 0) and
    (.sha256 | type == "string" and test("^[0-9a-fA-F]{64}$")) and
    (.pcr0 | type == "string" and test("^[0-9a-fA-F]{96}$"))
  )
' "$EIF_MANIFEST" >/dev/null

# Validate every artifact before starting any enclave. The manifest must come from
# the reviewed build; never derive its expected measurements from a downloaded EIF.
declare -a keymeld_ids=() keymeld_paths=()
while IFS= read -r entry; do
    keymeld_id="$(jq -er '.enclave_id' <<< "$entry")"
    keymeld_path="$(jq -er '.eif_path' <<< "$entry")"
    expected_sha="$(jq -er '.sha256 | ascii_downcase' <<< "$entry")"
    actual_sha="$(sha256sum -- "$keymeld_path")"
    [[ "${actual_sha%% *}" == "$expected_sha" ]] || { echo "EIF checksum mismatch for enclave $keymeld_id" >&2; exit 1; }
    measurements="$(nitro-cli describe-eif --eif-path "$keymeld_path")"
    expected_pcr0="$(jq -er '.pcr0 | ascii_downcase' <<< "$entry")"
    jq -e --arg pcr0 "$expected_pcr0" --arg pcr8 "${KEYMELD_ENCLAVE_PCR8,,}" '
        (.Measurements.PCR0 | ascii_downcase) == $pcr0 and
        (.Measurements.PCR8 | ascii_downcase) == $pcr8
    ' <<< "$measurements" >/dev/null || { echo "EIF measurements mismatch for enclave $keymeld_id" >&2; exit 1; }
    keymeld_ids+=("$keymeld_id")
    keymeld_paths+=("$keymeld_path")
done < <(jq -c 'sort_by(.enclave_id)[]' "$EIF_MANIFEST")

keymeld_temporary_env="$(mktemp "${keymeld_environment_file}.XXXXXX")"
trap 'rm -f -- "$keymeld_temporary_env"' EXIT
{
    printf '%s\n' '# Generated from reviewed per-enclave EIF artifacts.'
    printf '%s\n' 'export KEYMELD_ENVIRONMENT=production' 'export KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES=false'
    printf '%s\n' 'export CONFIG_PATH=config/production.yaml' 'unset KEYMELD_ENCLAVE_PCR0'
    printf 'export KEYMELD_ENCLAVE_PCR8=%q\n' "$KEYMELD_ENCLAVE_PCR8"
    printf 'export KEYMELD_EIF_MANIFEST=%q\n' "$EIF_MANIFEST"
} > "$keymeld_temporary_env"

for index in "${!keymeld_ids[@]}"; do
    keymeld_id="${keymeld_ids[$index]}"
    # Debug mode produces zero PCRs and is never accepted by the verifier.
    result="$(nitro-cli run-enclave --eif-path "${keymeld_paths[$index]}" \
        --memory "$keymeld_memory" --cpu-count "$keymeld_cpus" \
        --enclave-name "keymeld-enclave-$keymeld_id")"
    cid="$(jq -er '.EnclaveCID | select(type == "number" and . >= 4)' <<< "$result")"
    enclave="$(jq -er '.EnclaveID // .EnclaveId' <<< "$result")"
    printf 'export KEYMELD_ENCLAVE_%s_CID=%q\n' "$keymeld_id" "$cid" >> "$keymeld_temporary_env"
    printf 'Started enclave %s: %s (CID %s)\n' "$keymeld_id" "$enclave" "$cid"
done

# A concurrent deployment must not overwrite another deployment's configuration.
ln -- "$keymeld_temporary_env" "$keymeld_environment_file"
printf 'Deployment environment saved to %s. Provision the gateway signing key before starting the gateway.\n' "$keymeld_environment_file"
