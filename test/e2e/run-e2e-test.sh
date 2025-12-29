#!/usr/bin/env bash
# End-to-End Test Script for BitTorrent Blocker
# This script sets up and runs E2E tests on a real Linux system

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
QUEUE_NUM=0
IPSET_NAME="torrent_block_test"
TEST_PORT=6881
BLOCKER_BIN="../../bin/btblocker"

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_requirements() {
    log_info "Checking requirements..."

    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (needed for iptables/ipset)"
        exit 1
    fi

    # Check required commands
    for cmd in iptables ipset nc python3; do
        if ! command -v $cmd &> /dev/null; then
            log_error "Required command not found: $cmd"
            exit 1
        fi
    done

    # Check if blocker binary exists
    if [[ ! -f "$BLOCKER_BIN" ]]; then
        log_warn "Blocker binary not found, building..."
        (cd ../.. && make build)
    fi

    # Check kernel modules
    if ! lsmod | grep -q nfnetlink_queue; then
        log_info "Loading nfnetlink_queue module..."
        modprobe nfnetlink_queue
    fi

    log_info "✓ All requirements met"
}

setup_environment() {
    log_info "Setting up test environment..."

    # Create ipset
    ipset create -exist $IPSET_NAME hash:ip timeout 300

    # Setup iptables rules
    iptables -t mangle -A OUTPUT -p tcp --dport $TEST_PORT -j NFQUEUE --queue-num $QUEUE_NUM
    iptables -t mangle -A OUTPUT -p udp --dport 8000 -j NFQUEUE --queue-num $QUEUE_NUM

    # Drop traffic from banned IPs
    iptables -I OUTPUT -m set --match-set $IPSET_NAME src -j DROP

    log_info "✓ Environment setup complete"
}

cleanup_environment() {
    log_info "Cleaning up test environment..."

    # Remove iptables rules
    iptables -t mangle -D OUTPUT -p tcp --dport $TEST_PORT -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null || true
    iptables -t mangle -D OUTPUT -p udp --dport 8000 -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null || true
    iptables -D OUTPUT -m set --match-set $IPSET_NAME src -j DROP 2>/dev/null || true

    # Destroy ipset
    ipset destroy $IPSET_NAME 2>/dev/null || true

    # Kill blocker if running
    pkill -f btblocker || true

    log_info "✓ Cleanup complete"
}

start_blocker() {
    log_info "Starting btblocker..."

    # Start blocker in background
    $BLOCKER_BIN > /tmp/btblocker-test.log 2>&1 &
    BLOCKER_PID=$!

    # Wait for blocker to start
    sleep 2

    # Check if process is running
    if ! kill -0 $BLOCKER_PID 2>/dev/null; then
        log_error "Failed to start blocker"
        cat /tmp/btblocker-test.log
        exit 1
    fi

    log_info "✓ Blocker started (PID: $BLOCKER_PID)"
}

test_bittorrent_handshake() {
    log_info "Test 1: BitTorrent Handshake Detection"

    # Create BitTorrent handshake using Python
    python3 <<'EOF'
import socket
import struct
import time

# BitTorrent handshake structure
handshake = bytearray()
handshake.append(19)  # pstrlen
handshake.extend(b'BitTorrent protocol')
handshake.extend(b'\x00' * 8)  # reserved
handshake.extend(b'12345678901234567890')  # info_hash
handshake.extend(b'-UT3500-123456789012')  # peer_id

# Start a listener to accept connection
import threading
def server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('127.0.0.1', 6881))
    server_sock.listen(1)
    server_sock.settimeout(5)
    try:
        conn, addr = server_sock.accept()
        data = conn.recv(1024)
        conn.close()
    except:
        pass
    server_sock.close()

server_thread = threading.Thread(target=server)
server_thread.start()

time.sleep(1)

# Send handshake
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 6881))
    sock.send(handshake)
    sock.close()
except Exception as e:
    print(f"Connection handled: {e}")

server_thread.join(timeout=2)
EOF

    sleep 2

    # Check if IP was banned (we're testing localhost, so check logs)
    if grep -q "BLOCK" /tmp/btblocker-test.log; then
        log_info "✓ BitTorrent handshake detected and blocked"
        return 0
    else
        log_warn "⚠ BitTorrent handshake may not have been detected"
        return 1
    fi
}

test_udp_tracker() {
    log_info "Test 2: UDP Tracker Detection"

    python3 <<'EOF'
import socket
import struct

# UDP tracker connect packet
packet = struct.pack('>Q', 0x41727101980)  # protocol_id
packet += struct.pack('>I', 0)  # action: connect
packet += struct.pack('>I', 0x12345678)  # transaction_id

# Start UDP server
import threading
def server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind(('127.0.0.1', 8000))
    server_sock.settimeout(5)
    try:
        data, addr = server_sock.recvfrom(1024)
    except:
        pass
    server_sock.close()

server_thread = threading.Thread(target=server)
server_thread.start()

import time
time.sleep(1)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(packet, ('127.0.0.1', 8000))
sock.close()

server_thread.join(timeout=2)
EOF

    sleep 2

    if grep -q "UDP Tracker" /tmp/btblocker-test.log; then
        log_info "✓ UDP tracker detected"
        return 0
    else
        log_warn "⚠ UDP tracker detection inconclusive"
        return 1
    fi
}

test_normal_traffic() {
    log_info "Test 3: Normal Traffic (False Positive Check)"

    # Start a simple HTTP server
    python3 -m http.server 8080 > /dev/null 2>&1 &
    HTTP_SERVER_PID=$!
    sleep 2

    # Make HTTP request
    if curl -s http://localhost:8080 > /dev/null; then
        log_info "✓ Normal HTTP traffic passed through"
        kill $HTTP_SERVER_PID 2>/dev/null || true
        return 0
    else
        log_error "✗ Normal traffic was blocked (false positive)"
        kill $HTTP_SERVER_PID 2>/dev/null || true
        return 1
    fi
}

show_results() {
    log_info "==================================="
    log_info "Test Results Summary"
    log_info "==================================="

    echo ""
    echo "Blocker Log:"
    cat /tmp/btblocker-test.log
    echo ""

    log_info "IP Ban List:"
    ipset list $IPSET_NAME || true

    log_info "==================================="
}

# Main execution
main() {
    log_info "Starting E2E Tests for BitTorrent Blocker"
    log_info "=========================================="

    # Trap to ensure cleanup on exit
    trap cleanup_environment EXIT

    check_requirements
    cleanup_environment  # Clean up any previous test artifacts
    setup_environment
    start_blocker

    # Run tests
    TESTS_PASSED=0
    TESTS_FAILED=0

    test_bittorrent_handshake && ((TESTS_PASSED++)) || ((TESTS_FAILED++))
    test_udp_tracker && ((TESTS_PASSED++)) || ((TESTS_FAILED++))
    test_normal_traffic && ((TESTS_PASSED++)) || ((TESTS_FAILED++))

    show_results

    log_info "=========================================="
    log_info "Tests Passed: $TESTS_PASSED"
    log_info "Tests Failed: $TESTS_FAILED"
    log_info "=========================================="

    if [[ $TESTS_FAILED -eq 0 ]]; then
        log_info "✓ All E2E tests passed!"
        exit 0
    else
        log_error "✗ Some tests failed"
        exit 1
    fi
}

# Run main function
main "$@"
