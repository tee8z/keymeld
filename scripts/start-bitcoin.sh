#!/usr/bin/env bash
set -e

# Bitcoin Core starter script for KeyMeld
# Bitcoin Core starter for KeyMeld
BITCOIN_DATA_DIR="${PWD}/data/bitcoin"
mkdir -p "$BITCOIN_DATA_DIR"
mkdir -p "${PWD}/logs"

# Check if Bitcoin Core is already running
if pgrep -f "bitcoind.*regtest" >/dev/null 2>&1; then
    echo "⚠️  Bitcoin Core already running"
    echo "PID: $(pgrep -f "bitcoind.*regtest")"
    echo "To stop: pkill -f bitcoind"
    exit 0
fi

# Start bitcoind
echo "Bitcoin Core starting at $(date)" > "${PWD}/logs/bitcoin.log"
if command -v nix >/dev/null 2>&1; then
    # Start bitcoind and capture its output
    nix-shell -p bitcoin --run "bitcoind \
        -regtest \
        -server=1 \
        -daemon=1 \
        -datadir='$BITCOIN_DATA_DIR' \
        -debuglogfile='${PWD}/logs/bitcoin.log' \
        -rpcbind=127.0.0.1:18443 \
        -rpcallowip=127.0.0.1 \
        -rpcuser=keymeld \
        -rpcpassword=keymeldpass123 \
        -zmqpubrawblock=tcp://127.0.0.1:28332 \
        -zmqpubrawtx=tcp://127.0.0.1:28333 \
        -zmqpubhashtx=tcp://127.0.0.1:28334 \
        -zmqpubhashblock=tcp://127.0.0.1:28335 \
        -txindex=1 \
        -fallbackfee=0.00001 \
        -minrelaytxfee=0.00001 \
        -disablewallet=0 \
        -keypool=100 \
        -dbcache=512 \
        -maxconnections=20 \
        -assumevalid=0"
elif command -v bitcoind >/dev/null 2>&1; then
    bitcoind \
        -regtest \
        -server=1 \
        -daemon=1 \
        -datadir="$BITCOIN_DATA_DIR" \
        -debuglogfile="${PWD}/logs/bitcoin.log" \
        -rpcbind=127.0.0.1:18443 \
        -rpcallowip=127.0.0.1 \
        -rpcuser=keymeld \
        -rpcpassword=keymeldpass123 \
        -zmqpubrawblock=tcp://127.0.0.1:28332 \
        -zmqpubrawtx=tcp://127.0.0.1:28333 \
        -zmqpubhashtx=tcp://127.0.0.1:28334 \
        -zmqpubhashblock=tcp://127.0.0.1:28335 \
        -txindex=1 \
        -fallbackfee=0.00001 \
        -minrelaytxfee=0.00001 \
        -disablewallet=0 \
        -keypool=100 \
        -dbcache=512 \
        -maxconnections=20 \
        -assumevalid=0
else
    echo "❌ Bitcoin Core not found!"
    echo "Install with:"
    echo "  - Nix: nix-shell -p bitcoin"
    echo "  - apt: sudo apt install bitcoin-core"
    echo "  - brew: brew install bitcoin"
    exit 1
fi

sleep 5

# Check if it's running
if pgrep -f "bitcoind.*regtest" >/dev/null 2>&1; then
    PID=$(pgrep -f "bitcoind.*regtest")
    echo "$PID" > "$BITCOIN_DATA_DIR/bitcoind.pid"
    for i in {1..15}; do
        if bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 -datadir="$BITCOIN_DATA_DIR" getblockchaininfo >/dev/null 2>&1; then
            # Test twice more to ensure stability
            sleep 1
            if bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 -datadir="$BITCOIN_DATA_DIR" getblockchaininfo >/dev/null 2>&1; then
                sleep 1
                if bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 -datadir="$BITCOIN_DATA_DIR" getblockchaininfo >/dev/null 2>&1; then
                    break
                fi
            fi
        fi

        if [ $i -eq 15 ]; then
            echo "❌ Bitcoin RPC failed"
            exit 1
        fi
        sleep 2
    done

    # Final stability check
    sleep 2
    if ! bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 -datadir="$BITCOIN_DATA_DIR" getblockchaininfo >/dev/null 2>&1; then
        echo "❌ Bitcoin RPC unstable"
        exit 1
    fi

else
    echo "❌ Bitcoin Core failed to start"
    echo "Check logs in: $BITCOIN_DATA_DIR/regtest/debug.log"
    exit 1
fi
