#!/usr/bin/env bash
# Bitcoin RPC Batcher - Batches individual RPC requests to reduce load on bitcoind
#
# This script monitors a request queue directory and batches requests together:
# - send_to_address requests -> batched into sendmany calls
# - send_raw_transaction requests -> processed in controlled batches
#
# Usage: bitcoin-rpc-batcher.sh start|stop|status
#
# Environment:
#   BITCOIN_RPC_PORT     - Bitcoin RPC port (default: 18443)
#   BATCHER_QUEUE_DIR    - Queue directory (default: /tmp/keymeld-rpc-queue)
#   BATCHER_BATCH_SIZE   - Max requests per batch (default: 50)
#   BATCHER_POLL_MS      - Poll interval in ms (default: 100)

set -euo pipefail

QUEUE_DIR="${BATCHER_QUEUE_DIR:-/tmp/keymeld-rpc-queue}"
BATCH_SIZE="${BATCHER_BATCH_SIZE:-100}"
POLL_MS="${BATCHER_POLL_MS:-100}"
BITCOIN_RPC_PORT="${BITCOIN_RPC_PORT:-18443}"
PID_FILE="/tmp/keymeld-rpc-batcher.pid"
LOG_FILE="/tmp/keymeld-rpc-batcher.log"

BTC_CLI="bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 -rpcport=$BITCOIN_RPC_PORT"

# Atomic write: write to temp file then rename to avoid partial reads
atomic_write() {
    local file="$1"
    local content="$2"
    local tmp_file="${file}.tmp.$$"
    echo "$content" > "$tmp_file"
    mv "$tmp_file" "$file"
}

# Directories for different request types
FUNDING_REQ_DIR="$QUEUE_DIR/funding/requests"
FUNDING_RESP_DIR="$QUEUE_DIR/funding/responses"
BROADCAST_REQ_DIR="$QUEUE_DIR/broadcast/requests"
BROADCAST_RESP_DIR="$QUEUE_DIR/broadcast/responses"
CONFIRM_REQ_DIR="$QUEUE_DIR/confirm/requests"
CONFIRM_RESP_DIR="$QUEUE_DIR/confirm/responses"

init_queue_dirs() {
    mkdir -p "$FUNDING_REQ_DIR" "$FUNDING_RESP_DIR"
    mkdir -p "$BROADCAST_REQ_DIR" "$BROADCAST_RESP_DIR"
    mkdir -p "$CONFIRM_REQ_DIR" "$CONFIRM_RESP_DIR"
    # Clean any stale requests
    rm -f "$FUNDING_REQ_DIR"/* "$FUNDING_RESP_DIR"/* 2>/dev/null || true
    rm -f "$BROADCAST_REQ_DIR"/* "$BROADCAST_RESP_DIR"/* 2>/dev/null || true
    rm -f "$CONFIRM_REQ_DIR"/* "$CONFIRM_RESP_DIR"/* 2>/dev/null || true
}

# Process funding requests (send_to_address) - batch into sendmany
process_funding_batch() {
    local requests=()
    local request_files=()

    # Collect up to BATCH_SIZE requests
    shopt -s nullglob
    for req_file in "$FUNDING_REQ_DIR"/*.req; do
        [[ -f "$req_file" ]] || continue
        request_files+=("$req_file")
        requests+=("$(cat "$req_file")")
        if [[ ${#requests[@]} -ge $BATCH_SIZE ]]; then
            break
        fi
    done
    shopt -u nullglob

    [[ ${#requests[@]} -eq 0 ]] && return 0

    echo "[$(date -Iseconds)] Processing ${#requests[@]} funding requests" >> "$LOG_FILE"

    # Build sendmany JSON
    local sendmany_json="{"
    local first=true
    declare -A addr_amounts  # Track address -> amount mapping
    declare -A addr_ids      # Track address -> request_id mapping

    for req in "${requests[@]}"; do
        local address=$(echo "$req" | jq -r '.address')
        local amount=$(echo "$req" | jq -r '.amount')
        local request_id=$(echo "$req" | jq -r '.request_id')

        # Store for response mapping
        addr_ids["$address"]="$request_id"

        if [[ "$first" == "true" ]]; then
            first=false
        else
            sendmany_json+=","
        fi
        sendmany_json+="\"$address\": $amount"
    done
    sendmany_json+="}"

    # Execute sendmany with retry logic for 503 errors
    local txid
    local error=""
    local max_retries=5
    local retry_delay=2

    for attempt in $(seq 1 $max_retries); do
        if txid=$($BTC_CLI -rpcwallet=keymeld_coordinator sendmany "" "$sendmany_json" 2>&1); then
            echo "[$(date -Iseconds)] Batch funded: $txid" >> "$LOG_FILE"

            # Write success responses for all requests (atomic writes)
            for req_file in "${request_files[@]}"; do
                local request_id=$(jq -r '.request_id' < "$req_file")
                atomic_write "$FUNDING_RESP_DIR/$request_id.resp" "{\"success\": true, \"txid\": \"$txid\"}"
                rm -f "$req_file"
            done
            return 0
        else
            error="$txid"
            if [[ "$error" == *"503"* ]] && [[ $attempt -lt $max_retries ]]; then
                echo "[$(date -Iseconds)] Batch funding got 503, retrying in ${retry_delay}s (attempt $attempt/$max_retries)..." >> "$LOG_FILE"
                sleep $retry_delay
                retry_delay=$((retry_delay * 2))
                continue
            fi

            echo "[$(date -Iseconds)] Batch funding failed: $error" >> "$LOG_FILE"

            # Write error responses (atomic writes)
            for req_file in "${request_files[@]}"; do
                local request_id=$(jq -r '.request_id' < "$req_file")
                atomic_write "$FUNDING_RESP_DIR/$request_id.resp" "{\"success\": false, \"error\": \"$error\"}"
                rm -f "$req_file"
            done
            return 0
        fi
    done

    return 0
}

# Process broadcast requests (send_raw_transaction) - process in controlled batches
process_broadcast_batch() {
    local count=0

    shopt -s nullglob
    for req_file in "$BROADCAST_REQ_DIR"/*.req; do
        [[ -f "$req_file" ]] || continue
        [[ $count -ge $BATCH_SIZE ]] && break

        local request_id=$(jq -r '.request_id' < "$req_file")
        local raw_tx=$(jq -r '.raw_tx' < "$req_file")

        local txid
        local error=""
        if txid=$($BTC_CLI sendrawtransaction "$raw_tx" 2>&1); then
            atomic_write "$BROADCAST_RESP_DIR/$request_id.resp" "{\"success\": true, \"txid\": \"$txid\"}"
        else
            error="$txid"
            atomic_write "$BROADCAST_RESP_DIR/$request_id.resp" "{\"success\": false, \"error\": \"$error\"}"
        fi

        rm -f "$req_file"
        count=$((count + 1))
    done
    shopt -u nullglob

    [[ $count -gt 0 ]] && echo "[$(date -Iseconds)] Processed $count broadcast requests" >> "$LOG_FILE"
    return 0
}

# Process confirmation requests (get_transaction) - batch check confirmations
# Optimized: group requests by txid to avoid redundant RPC calls
process_confirm_batch() {
    local count=0

    # First pass: collect all requests and group by txid
    declare -A txid_requests  # txid -> space-separated list of "request_id:min_conf:req_file"
    declare -A txid_results   # txid -> cached gettransaction result
    declare -A txid_errors    # txid -> error message if any

    shopt -s nullglob
    for req_file in "$CONFIRM_REQ_DIR"/*.req; do
        [[ -f "$req_file" ]] || continue
        [[ $count -ge $BATCH_SIZE ]] && break

        local request_id=$(jq -r '.request_id' < "$req_file")
        local txid=$(jq -r '.txid' < "$req_file")
        local min_confirmations=$(jq -r '.min_confirmations // 1' < "$req_file")

        # Append to list for this txid
        txid_requests["$txid"]+="$request_id:$min_confirmations:$req_file "
        count=$((count + 1))
    done
    shopt -u nullglob

    [[ $count -eq 0 ]] && return 0

    # Second pass: call gettransaction once per unique txid
    # Must specify wallet since multiple wallets may be loaded during stress tests
    for txid in "${!txid_requests[@]}"; do
        local result
        if result=$($BTC_CLI -rpcwallet=keymeld_coordinator gettransaction "$txid" 2>&1); then
            txid_results["$txid"]="$result"
        else
            txid_errors["$txid"]="$result"
        fi
    done

    # Third pass: write responses for all requests
    local processed=0
    for txid in "${!txid_requests[@]}"; do
        for entry in ${txid_requests["$txid"]}; do
            local request_id="${entry%%:*}"
            local rest="${entry#*:}"
            local min_confirmations="${rest%%:*}"
            local req_file="${rest#*:}"

            if [[ -n "${txid_errors[$txid]:-}" ]]; then
                local error="${txid_errors[$txid]}"
                atomic_write "$CONFIRM_RESP_DIR/$request_id.resp" "{\"success\": false, \"error\": \"$error\"}"
            else
                local result="${txid_results[$txid]}"
                local confirmations=$(echo "$result" | jq -r '.confirmations // 0')
                if [[ "$confirmations" -ge "$min_confirmations" ]]; then
                    atomic_write "$CONFIRM_RESP_DIR/$request_id.resp" "{\"success\": true, \"confirmations\": $confirmations, \"confirmed\": true}"
                else
                    atomic_write "$CONFIRM_RESP_DIR/$request_id.resp" "{\"success\": true, \"confirmations\": $confirmations, \"confirmed\": false}"
                fi
            fi

            rm -f "$req_file"
            processed=$((processed + 1))
        done
    done

    [[ $processed -gt 0 ]] && echo "[$(date -Iseconds)] Processed $processed confirm requests (${#txid_requests[@]} unique txids)" >> "$LOG_FILE"
    return 0
}

# Main batcher loop
run_batcher() {
    echo "[$(date -Iseconds)] Bitcoin RPC Batcher started (poll=${POLL_MS}ms, batch_size=$BATCH_SIZE)" >> "$LOG_FILE"
    echo "[$(date -Iseconds)] Queue dir: $QUEUE_DIR" >> "$LOG_FILE"

    while true; do
        process_funding_batch
        process_broadcast_batch
        process_confirm_batch

        # Sleep for poll interval
        sleep "0.$(printf '%03d' $POLL_MS)"
    done
}

start() {
    if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "Batcher already running (PID: $(cat "$PID_FILE"))"
        return 0
    fi

    init_queue_dirs

    echo "Starting Bitcoin RPC Batcher..."
    run_batcher &
    local pid=$!
    echo "$pid" > "$PID_FILE"
    echo "Batcher started (PID: $pid)"
    echo "Queue directory: $QUEUE_DIR"
    echo "Log file: $LOG_FILE"
}

stop() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "Stopping batcher (PID: $pid)..."
            kill "$pid" 2>/dev/null || true
            sleep 0.5
            kill -9 "$pid" 2>/dev/null || true
            rm -f "$PID_FILE"
            echo "Batcher stopped"
        else
            echo "Batcher not running (stale PID file)"
            rm -f "$PID_FILE"
        fi
    else
        echo "Batcher not running"
    fi
}

status() {
    if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "Batcher running (PID: $(cat "$PID_FILE"))"
        echo "Queue directory: $QUEUE_DIR"
        echo "Pending funding requests: $(ls -1 "$FUNDING_REQ_DIR"/*.req 2>/dev/null | wc -l)"
        echo "Pending broadcast requests: $(ls -1 "$BROADCAST_REQ_DIR"/*.req 2>/dev/null | wc -l)"
    else
        echo "Batcher not running"
    fi
}

case "${1:-}" in
    start) start ;;
    stop) stop ;;
    status) status ;;
    *)
        echo "Usage: $0 start|stop|status"
        exit 1
        ;;
esac
