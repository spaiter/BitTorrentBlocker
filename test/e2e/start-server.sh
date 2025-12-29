#!/bin/bash
# Script to start btblocker server in E2E environment

set -e

echo "==================================="
echo "Starting BitTorrent Blocker Server"
echo "==================================="

# Load kernel modules (if available)
modprobe nfnetlink_queue 2>/dev/null || echo "Warning: Could not load nfnetlink_queue (may need privileged mode)"
modprobe xt_NFQUEUE 2>/dev/null || echo "Warning: Could not load xt_NFQUEUE"

# Create ipset
ipset create -exist torrent_block hash:ip timeout 300

# Setup iptables rules
echo "Configuring iptables..."
iptables -t mangle -A PREROUTING -j NFQUEUE --queue-num 0
iptables -I INPUT -m set --match-set torrent_block src -j DROP
iptables -I FORWARD -m set --match-set torrent_block src -j DROP

# Show current configuration
echo "Current iptables rules:"
iptables -L -n -v
echo ""
echo "Current ipset:"
ipset list torrent_block
echo ""

# Start btblocker
echo "Starting btblocker..."
exec /app/bin/btblocker
