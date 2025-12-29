#!/bin/bash
# Simplified E2E test that tests the packet analysis without nfqueue
# This can run in Docker on Windows

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

log_info "======================================"
log_info "BitTorrent Blocker Simple E2E Test"
log_info "======================================"
log_info ""

# Test the analyzer directly with real packets
log_info "Test 1: BitTorrent Handshake Detection"
docker exec btblocker-e2e-server sh -c 'cd /app && go run test/e2e/test-analyzer.go handshake'

log_info ""
log_info "Test 2: UDP Tracker Detection"
docker exec btblocker-e2e-server sh -c 'cd /app && go run test/e2e/test-analyzer.go udp_tracker'

log_info ""
log_info "Test 3: DHT Query Detection"
docker exec btblocker-e2e-server sh -c 'cd /app && go run test/e2e/test-analyzer.go dht'

log_info ""
log_info "Test 4: uTP Detection"
docker exec btblocker-e2e-server sh -c 'cd /app && go run test/e2e/test-analyzer.go utp'

log_info ""
log_info "Test 5: MSE/PE Encryption Detection"
docker exec btblocker-e2e-server sh -c 'cd /app && go run test/e2e/test-analyzer.go mse'

log_info ""
log_info "Test 6: Normal HTTPS Traffic (False Positive Check)"
docker exec btblocker-e2e-server sh -c 'cd /app && go run test/e2e/test-analyzer.go https'

log_info ""
log_info "Test 7: Normal DNS Query (False Positive Check)"
docker exec btblocker-e2e-server sh -c 'cd /app && go run test/e2e/test-analyzer.go dns'

log_info ""
log_info "======================================"
log_info "All E2E Tests Completed!"
log_info "======================================"
