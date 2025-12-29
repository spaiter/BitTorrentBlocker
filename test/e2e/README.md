# End-to-End Tests

This directory contains end-to-end tests that simulate real-world deployment on NixOS servers with actual network traffic interception.

## Overview

The E2E tests create a complete NixOS VM environment that:
1. Deploys the BitTorrent blocker as a system service
2. Configures iptables/nftables rules to redirect traffic
3. Simulates BitTorrent clients attempting connections
4. Verifies traffic is properly blocked and IPs are banned
5. Tests that normal traffic passes through unaffected

## Test Scenarios

### 1. Full Deployment Test
- Installs blocker as systemd service
- Configures netfilter queue
- Sets up ipset for IP banning
- Tests service lifecycle (start/stop/restart)

### 2. Traffic Interception Test
- Creates virtual network interfaces
- Simulates BitTorrent handshake attempts
- Verifies packets are queued and analyzed
- Confirms blocking verdicts are applied

### 3. IP Banning Test
- Sends BitTorrent traffic from test client
- Verifies IP is added to ipset blocklist
- Confirms subsequent packets are dropped
- Tests ban expiration

### 4. Normal Traffic Test
- Sends HTTPS, DNS, SSH traffic
- Verifies no false positives
- Measures performance impact

## Running E2E Tests

### Using NixOS Test Framework

```bash
# Run all E2E tests
nix-build e2e.nix

# Run specific test
nix-build e2e.nix -A tests.deployment

# Interactive debugging
nix-build e2e.nix -A tests.deployment.driver
./result/bin/nixos-test-driver
```

### Using Docker with NixOS

```bash
# Build and run E2E environment
cd test/e2e
docker-compose up --build

# Run tests
docker-compose run e2e-tests
```

### Manual Testing on NixOS Server

```bash
# Copy files to NixOS server
scp -r . user@nixos-server:/tmp/btblocker-e2e

# SSH into server
ssh user@nixos-server

# Run test script
cd /tmp/btblocker-e2e
sudo ./run-e2e-test.sh
```

## Test Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ NixOS VM Test Environment                                   │
│                                                              │
│  ┌──────────────┐      ┌──────────────┐                    │
│  │ Test Client  │      │ Test Server  │                    │
│  │              │      │              │                    │
│  │ Simulates    │─────▶│ btblocker    │                    │
│  │ BitTorrent   │      │ Service      │                    │
│  │ Traffic      │      │              │                    │
│  └──────────────┘      │ ┌──────────┐ │                    │
│                        │ │ nfqueue  │ │                    │
│                        │ │ iptables │ │                    │
│                        │ │ ipset    │ │                    │
│                        │ └──────────┘ │                    │
│                        └──────────────┘                    │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- NixOS or Nix package manager
- Root/sudo access (for netfilter operations)
- 2GB RAM minimum for VM tests
- IPv4 networking enabled

## Test Results

Expected outcomes:
- ✓ Service starts and runs successfully
- ✓ BitTorrent traffic is blocked
- ✓ IPs are added to ipset
- ✓ Normal traffic passes through
- ✓ 0% false positive rate
- ✓ Low performance impact (<5% CPU)

## Troubleshooting

### Service won't start
```bash
# Check logs
journalctl -u btblocker -n 100

# Verify nfqueue module
lsmod | grep nfnetlink_queue

# Check iptables rules
iptables -L -n -v
```

### Traffic not being blocked
```bash
# Verify queue is receiving packets
cat /proc/net/netfilter/nfnetlink_queue

# Check ipset
ipset list torrent_block

# Test blocker manually
echo "test packet" | sudo ./btblocker
```

## Configuration Files

- `e2e.nix` - NixOS test configuration
- `docker-compose.yml` - Docker-based E2E environment
- `run-e2e-test.sh` - Shell script for manual testing
- `nixos-module.nix` - NixOS module for production deployment
