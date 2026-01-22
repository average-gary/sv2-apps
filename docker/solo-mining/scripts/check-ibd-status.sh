#!/bin/bash
# =============================================================================
# Check Bitcoin Core IBD (Initial Block Download) Status
# =============================================================================
#
# Run this script to monitor sync progress:
#   ./scripts/check-ibd-status.sh
#
# Or watch continuously:
#   watch -n 10 ./scripts/check-ibd-status.sh
#
# =============================================================================

set -e

# Load environment if exists
if [ -f "docker_env.solo" ]; then
    export $(grep -v '^#' docker_env.solo | xargs)
fi

RPC_USER="${BITCOIN_RPC_USER:-sv2user}"
RPC_PASS="${BITCOIN_RPC_PASS:-sv2password}"

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "bitcoind-testnet4"; then
    echo "ERROR: bitcoind-testnet4 container is not running"
    echo "Start it with: docker compose -f docker-compose-solo.yml --env-file docker_env.solo up -d bitcoind"
    exit 1
fi

# Get blockchain info
INFO=$(docker exec bitcoind-testnet4 bitcoin-cli -testnet4 \
    -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" \
    getblockchaininfo 2>/dev/null)

if [ $? -ne 0 ]; then
    echo "ERROR: Could not connect to Bitcoin Core RPC"
    echo "The node may still be starting up. Try again in a moment."
    exit 1
fi

# Parse values
BLOCKS=$(echo "$INFO" | grep '"blocks"' | grep -o '[0-9]*')
HEADERS=$(echo "$INFO" | grep '"headers"' | grep -o '[0-9]*')
PROGRESS=$(echo "$INFO" | grep '"verificationprogress"' | grep -oE '[0-9]+\.[0-9]+')
IBD=$(echo "$INFO" | grep '"initialblockdownload"' | grep -oE 'true|false')

# Calculate percentage
if [ -n "$PROGRESS" ]; then
    PERCENT=$(echo "$PROGRESS * 100" | bc -l 2>/dev/null | cut -c1-5 || echo "calculating...")
else
    PERCENT="0"
fi

# Display status
echo "============================================"
echo "  Bitcoin Core Testnet4 Sync Status"
echo "============================================"
echo ""
echo "  Blocks:    $BLOCKS / $HEADERS"
echo "  Progress:  ${PERCENT}%"
echo "  IBD:       $IBD"
echo ""

if [ "$IBD" = "false" ]; then
    echo "  STATUS: SYNCED - Ready for mining!"
    echo ""
    echo "  JDC and Translator should now be starting..."
    echo "  Check with: docker ps"
    echo ""
else
    REMAINING=$((HEADERS - BLOCKS))
    echo "  STATUS: SYNCING - $REMAINING blocks remaining"
    echo ""
    echo "  JDC and Translator are waiting for sync to complete."
    echo "  This can take 30 minutes to several hours depending on"
    echo "  your internet connection and hardware."
    echo ""
    echo "  Monitor progress with:"
    echo "    watch -n 10 ./scripts/check-ibd-status.sh"
    echo ""
fi
echo "============================================"
