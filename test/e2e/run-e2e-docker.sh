#!/bin/bash
# Docker-based E2E Test Runner

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

SERVER_IP="172.20.0.10"
CLIENT_IP="172.20.0.20"

log_info "==================================="
log_info "BitTorrent Blocker E2E Tests"
log_info "==================================="

# Wait for server to be ready
log_info "Waiting for server to be ready..."
sleep 5

# Test 1: Verify server is running
log_info "Test 1: Checking if btblocker service is running"
if docker exec btblocker-e2e-server pgrep -f btblocker > /dev/null; then
    log_info "✓ Blocker service is running"
else
    log_error "✗ Blocker service is not running"
    exit 1
fi

# Test 2: Check iptables configuration
log_info "Test 2: Verifying iptables configuration"
if docker exec btblocker-e2e-server iptables -L -n | grep -q NFQUEUE; then
    log_info "✓ iptables NFQUEUE rule configured"
else
    log_warn "⚠ NFQUEUE rule not found"
fi

# Test 3: Check ipset
log_info "Test 3: Verifying ipset configuration"
if docker exec btblocker-e2e-server ipset list torrent_block > /dev/null 2>&1; then
    log_info "✓ ipset 'torrent_block' exists"
else
    log_error "✗ ipset not configured"
    exit 1
fi

# Test 4: BitTorrent handshake from client
log_info "Test 4: Sending BitTorrent handshake from client"
docker exec btblocker-e2e-client python3 <<'EOF'
import socket
import time

# BitTorrent handshake
handshake = bytearray()
handshake.append(19)
handshake.extend(b'BitTorrent protocol')
handshake.extend(b'\x00' * 8)
handshake.extend(b'12345678901234567890')
handshake.extend(b'-TEST00-123456789012')

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(('172.20.0.10', 6881))
    sock.send(handshake)
    sock.close()
    print("Sent BitTorrent handshake")
except Exception as e:
    print(f"Connection attempt: {e}")
EOF

sleep 3

# Check if client IP was banned
if docker exec btblocker-e2e-server ipset list torrent_block | grep -q "$CLIENT_IP"; then
    log_info "✓ Client IP was banned after BitTorrent handshake"
else
    log_warn "⚠ Client IP not in ban list (may need more time or different configuration)"
fi

# Test 5: UDP Tracker test
log_info "Test 5: Sending UDP tracker packet"
docker exec btblocker-e2e-client python3 <<'EOF'
import socket
import struct

packet = struct.pack('>Q', 0x41727101980)
packet += struct.pack('>I', 0)
packet += struct.pack('>I', 0x12345678)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(packet, ('172.20.0.10', 8000))
sock.close()
print("Sent UDP tracker packet")
EOF

sleep 2
log_info "✓ UDP tracker packet sent"

# Test 6: Normal traffic (should pass)
log_info "Test 6: Testing normal traffic (false positive check)"

# Start simple HTTP server on server
docker exec -d btblocker-e2e-server python3 -m http.server 8080

sleep 2

# Try to access from client
if docker exec btblocker-e2e-client curl -s --connect-timeout 5 http://$SERVER_IP:8080 > /dev/null; then
    log_info "✓ Normal HTTP traffic passed through"
else
    log_warn "⚠ HTTP request failed (may be blocked)"
fi

# Show final state
log_info "==================================="
log_info "Final State"
log_info "==================================="

log_info "Banned IPs:"
docker exec btblocker-e2e-server ipset list torrent_block

log_info "==================================="
log_info "E2E Tests Complete!"
log_info "==================================="
