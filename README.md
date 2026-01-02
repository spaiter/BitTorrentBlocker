# BitTorrent Blocker

[![Release](https://img.shields.io/github/v/release/spaiter/BitTorrentBlocker)](https://github.com/spaiter/BitTorrentBlocker/releases)
[![CI/CD Pipeline](https://github.com/spaiter/BitTorrentBlocker/actions/workflows/pipeline.yml/badge.svg)](https://github.com/spaiter/BitTorrentBlocker/actions/workflows/pipeline.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/spaiter/BitTorrentBlocker)](https://goreportcard.com/report/github.com/spaiter/BitTorrentBlocker)
[![codecov](https://codecov.io/gh/spaiter/BitTorrentBlocker/branch/main/graph/badge.svg)](https://codecov.io/gh/spaiter/BitTorrentBlocker)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Cachix Cache](https://img.shields.io/badge/cachix-btblocker-blue.svg)](https://btblocker.cachix.org)

A high-performance Go library and CLI tool for detecting and blocking BitTorrent traffic using Deep Packet Inspection (DPI). Designed primarily for **VPS and home servers** that need to prevent BitTorrent usage to comply with local regulations or service provider terms.

## Primary Use Case

**Server Liability Protection**: In many jurisdictions, server operators can be held liable for BitTorrent traffic passing through their infrastructure, especially when:
- Running VPN/proxy services where users might torrent copyrighted content
- Operating in countries with strict copyright enforcement laws
- Hosting services where terms explicitly prohibit P2P file sharing
- Managing shared hosting where one user's activity affects others

This tool helps server administrators **proactively block BitTorrent** at the network level to:
- ✅ Protect against legal liability from users' torrent activity
- ✅ Comply with local regulations and ISP/datacenter terms of service
- ✅ Prevent bandwidth abuse from P2P traffic
- ✅ Avoid DMCA notices and copyright complaints
- ✅ Maintain service quality by preventing network congestion

**Common deployment scenarios:**
- VPN/VPS providers in countries with strict copyright laws
- Educational institutions preventing unauthorized file sharing
- Corporate networks enforcing acceptable use policies
- ISPs complying with regulatory requirements
- Home servers protecting owners from user liability

The tool provides **defense-in-depth** - even if users don't intend to violate policies, it prevents accidental BitTorrent usage that could lead to legal complications.

## Features

- **Multi-Protocol Detection**: Identifies BitTorrent traffic over TCP and UDP
- **Deep Packet Inspection**: Uses signature-based and behavioral analysis
- **Protocol Coverage**:
  - Standard BitTorrent handshakes
  - **MSE/PE Encryption** (Message Stream Encryption) - Critical for encrypted traffic
  - **LSD** (Local Service Discovery/BEP 14) - Local peer discovery
  - **Extended Protocol** (BEP 10) - ut_metadata, ut_holepunch, etc.
  - **FAST Extension** (BEP 6) - Suggest Piece, Have All/None, etc.
  - UDP tracker protocol (Connect/Announce/Scrape)
  - DHT (Distributed Hash Table/BEP 5)
  - PEX (Peer Exchange/BEP 11)
  - uTP (Micro Transport Protocol/BEP 29)
  - BitTorrent v2 support
  - Encrypted/obfuscated traffic via entropy analysis
- **Extensive Signature Database**: 95+ protocol signatures, 60+ client identifiers
- **SOCKS5 Unwrapping**: Detects BitTorrent traffic tunneled through SOCKS proxies
- **Automatic IP Banning**: Integrates with Linux ipset for persistent blocking
- **Whitelist Support**: Excludes common ports (HTTP, HTTPS, SSH, DNS)

## Architecture

```
cmd/btblocker/main.go      - CLI application entry point
internal/blocker/
  ├── blocker.go           - Main blocker service
  ├── analyzer.go          - Packet analysis engine
  ├── detectors.go         - Protocol detection functions
  ├── signatures.go        - Signature databases
  ├── ipban.go             - IP banning with caching
  └── config.go            - Configuration management
```

## How It Works

The blocker uses **passive packet monitoring** (like ndpiReader/Wireshark):

1. **Captures** packet copies via libpcap without blocking traffic flow
2. **Analyzes** packets asynchronously in background goroutines
3. **Detects** BitTorrent traffic using 11 complementary DPI techniques
4. **Bans** detected IPs via Linux ipset for 5 hours
5. **Blocks** traffic from banned IPs using pre-configured nftables/iptables rules

**Key advantages:**
- ✅ Zero latency - traffic flows normally during analysis
- ✅ No packet verdict delays - analysis happens in background
- ✅ Simpler setup - no iptables NFQUEUE rules needed
- ✅ Better performance - asynchronous processing

## Prerequisites

- Go 1.20 or later
- Linux with libpcap support (standard on most distributions)
- ipset utility (for IP banning)
- nftables or iptables (for DROP rules)
- Root/CAP_NET_ADMIN privileges (for packet capture and ipset)

## Installation

### Binary Releases (Recommended for Production)

Download pre-built binaries for your platform:

```bash
# Linux (amd64)
curl -LO https://github.com/spaiter/BitTorrentBlocker/releases/latest/download/btblocker-VERSION-linux-amd64.tar.gz
tar -xzf btblocker-VERSION-linux-amd64.tar.gz
sudo mv btblocker-VERSION-linux-amd64 /usr/local/bin/btblocker
sudo chmod +x /usr/local/bin/btblocker

# Verify checksum
curl -LO https://github.com/spaiter/BitTorrentBlocker/releases/latest/download/btblocker-VERSION-linux-amd64.tar.gz.sha256
sha256sum -c btblocker-VERSION-linux-amd64.tar.gz.sha256
```

**Available platforms:** Linux (amd64, arm64, arm), Windows (amd64, arm64), macOS (amd64, arm64)

See all releases: https://github.com/spaiter/BitTorrentBlocker/releases

### Docker

```bash
# Pull latest image
docker pull ghcr.io/spaiter/btblocker:latest

# Run with required capabilities
docker run --rm \
  --cap-add=NET_ADMIN \
  --network host \
  ghcr.io/spaiter/btblocker:latest

# Docker Compose (Compose V2 - built into Docker)
cat > compose.yml << EOF
services:
  btblocker:
    image: ghcr.io/spaiter/btblocker:latest
    cap_add:
      - NET_ADMIN
    network_mode: host
    restart: unless-stopped
EOF

docker compose up -d
```

### NixOS / Nix (Recommended for NixOS users)

The blocker includes a **complete NixOS module** that handles all configuration automatically. No need to manually configure systemd services, ipset, or firewall rules!

#### Quick Start with Flakes

Add BitTorrentBlocker to your system flake and import the module:

```nix
# ~/my-server/flake.nix (or /etc/nixos/flake.nix)
{
  description = "My NixOS Configuration";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    bittorrent-blocker.url = "github:spaiter/BitTorrentBlocker";
    bittorrent-blocker.inputs.nixpkgs.follows = "nixpkgs";  # Use same nixpkgs
  };

  outputs = { self, nixpkgs, bittorrent-blocker, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./configuration.nix  # Your existing configuration

        # Import the official btblocker module
        bittorrent-blocker.nixosModules.default

        # Configure btblocker
        {
          services.btblocker = {
            enable = true;
            interface = "eth0";  # Your network interface
            logLevel = "info";

            # Optional: customize settings
            banDuration = 18000;          # 5 hours (default)
            firewallBackend = "nftables";  # or "iptables"
            cleanupOnStop = false;        # keep banned IPs on stop
          };
        }
      ];
    };
  };
}
```

**Deploy to your system:**
```bash
# Update flake inputs to get latest version
nix flake update bittorrent-blocker

# Rebuild your system
sudo nixos-rebuild switch --flake .#myhost

# Check service status
sudo systemctl status btblocker

# View logs
sudo journalctl -u btblocker -f

# Check banned IPs
sudo ipset list torrent_block
```

#### What the Module Does Automatically

- ✅ **Installs btblocker binary** from Cachix (instant, pre-built)
- ✅ **Creates systemd service** with CAP_NET_ADMIN capability
- ✅ **Sets up ipset** (destroyed and recreated on each start for clean state)
- ✅ **Configures firewall rules** (nftables or iptables, your choice)
- ✅ **Loads kernel modules** (ip_set, ip_set_hash_ip)
- ✅ **Handles all environment variables** automatically
- ✅ **Cleans up on stop** (removes firewall rules, optionally destroys ipset)

**No manual configuration needed!** Just enable the service and set your interface.

#### Binary Cache

Pre-built binaries are available at https://btblocker.cachix.org

Nix will prompt to trust the cache on first use. This means instant installation without building from source.

#### Quick Test (Without Installing)

```bash
# Try it on any Linux with Nix (no installation required)
nix run github:spaiter/BitTorrentBlocker -- --version

# Install to your user profile (non-NixOS)
nix profile install github:spaiter/BitTorrentBlocker
```

### From Source

```bash
# Clone the repository
git clone https://github.com/spaiter/BitTorrentBlocker
cd BitTorrentBlocker

# Download dependencies
go mod tidy

# Build
make build

# Or manually
go build -o bin/btblocker ./cmd/btblocker
```

## Usage

### Basic Usage

```bash
# Run with default configuration (requires root)
sudo ./bin/btblocker

# The blocker will:
# 1. Start capturing packets on eth0 (default interface)
# 2. Analyze traffic in the background
# 3. Automatically ban detected IPs via ipset
```

### Manual Setup (if not using NixOS module)

Before running the blocker, set up ipset and firewall rules:

```bash
# 1. Create ipset for banned IPs (5-hour timeout)
sudo ipset create torrent_block hash:ip timeout 18000

# 2. Configure firewall to DROP traffic from banned IPs
# Using nftables (recommended):
sudo nft add table inet btblocker
sudo nft add chain inet btblocker input { type filter hook input priority 0 \; policy accept \; }
sudo nft add chain inet btblocker forward { type filter hook forward priority 0 \; policy accept \; }
sudo nft add rule inet btblocker input ip saddr @torrent_block drop
sudo nft add rule inet btblocker forward ip saddr @torrent_block drop

# OR using iptables (alternative):
sudo iptables -I INPUT -m set --match-set torrent_block src -j DROP
sudo iptables -I FORWARD -m set --match-set torrent_block src -j DROP

# 3. Run the blocker
sudo INTERFACE=eth0 LOG_LEVEL=info ./bin/btblocker
```

**Note:** The NixOS module handles all of this automatically.

### Configuration

The blocker uses sensible defaults but can be customized:

```go
config := blocker.Config{
    Interface:        "eth0",  // Network interface to monitor
    EntropyThreshold: 7.6,     // Entropy threshold for encrypted traffic
    MinPayloadSize:   60,      // Minimum payload size for analysis
    IPSetName:        "torrent_block",
    BanDuration:      18000,   // 5 hours in seconds
    LogLevel:         "info",  // Log level: error, warn, info, debug
}
```

**Environment Variables:**
- `INTERFACE` - Network interface to monitor (default: `eth0`)
- `LOG_LEVEL` - Logging verbosity (default: `info`)
- `BAN_DURATION` - Ban duration in seconds (default: `18000` = 5 hours)

**Log Levels:**
- `error` - Only critical errors
- `warn` - Warnings and errors
- `info` - General information, detection events (default)
- `debug` - Detailed packet analysis including whitelisted traffic

**Examples:**
```bash
# Custom interface and debug logging
sudo INTERFACE=ens33 LOG_LEVEL=debug ./bin/btblocker

# Short ban duration for testing (30 seconds)
sudo BAN_DURATION=30 ./bin/btblocker
```

## How It Works

### Detection Methods

The blocker employs 11 complementary detection techniques, ordered by performance (fastest first) while maintaining high specificity:

1. **LSD Detection** (BEP 14): Local Service Discovery multicast traffic
   - IPv4 multicast (239.192.152.143:6771) and IPv6 (ff15::efc0:988f:6771)
   - BT-SEARCH HTTP-style messages
   - Infohash + Port combinations

2. **MSE/PE Encryption Detection**: Message Stream Encryption (CRITICAL)
   - Verification Constant (VC) pattern: 8 consecutive zero bytes
   - High entropy DH public key detection (>7.0 bits/byte in first 96 bytes)
   - Detects encrypted BitTorrent traffic that evades signature-based detection

3. **Extended Protocol Detection** (BEP 10): Extension protocol messages
   - Message ID 20 (0x14) detection
   - ut_metadata, ut_holepunch, upload_only, share_mode support
   - Bencode dictionary validation

4. **FAST Extension Detection** (BEP 6): FAST protocol messages
   - Message IDs 13-17: Suggest Piece, Have All, Have None, Reject Request, Allowed Fast
   - Message length validation for each type

5. **SOCKS Proxy Detection**: Blocks SOCKS4/SOCKS5 proxy connections
   - Connection attempt pattern matching
   - SOCKS5 UDP unwrapping for inner traffic inspection

6. **UDP Tracker Protocol**: Deep tracker packet validation
   - Magic protocol ID (0x41727101980)
   - Action types (Connect/Announce/Scrape)
   - PeerID prefix validation (60+ clients)

7. **HTTP-based BitTorrent Detection**: HTTP protocol analysis
   - **WebSeed Protocol** (BEP 19) - HTTP-based piece downloading
   - **Bitcomet Persistent Seed** - Proprietary HTTP protocol
   - **User-Agent Detection** - Identifies BitTorrent clients (Azureus, BitTorrent, BTWebClient, Shareaza, FlashGet)

8. **Signature Matching**: 95+ known BitTorrent protocol patterns
   - Protocol handshakes (`\x13BitTorrent protocol`)
   - PEX extension keys (`ut_pex`, `added`, `dropped`, `added6`)
   - DHT keys (ping, get_peers, announce_peer, find_node)
   - Extension protocol signatures (ut_metadata, ut_holepunch, yourip, reqq)
   - Magnet links, tracker URLs
   - BitTorrent v2 keys (piece layers, file tree)
   - Client PeerIDs: qBittorrent, Transmission, µTorrent, libtorrent, Deluge, etc.
   - WebSeed and Bitcomet HTTP patterns

9. **uTP Detection** (BEP 29): Micro Transport Protocol analysis
   - Version and type validation
   - Extension chain verification
   - Header structure validation

10. **DHT Analysis** (BEP 5): Enhanced structural bencode validation (Suricata-inspired)
    - Query/Response/Error type checking (y:q, y:r, y:e)
    - Suricata-specific prefix validation (d1:ad, d1:rd, d2:ip, d1:el)
    - Transaction ID presence
    - DHT-specific keys (nodes, values, token)
    - **Node structure validation** - IPv4 (26 bytes/node) and IPv6 (38 bytes/node)
    - Binary node list length verification

11. **Entropy Analysis**: Last-resort detection for fully encrypted traffic
    - Shannon entropy calculation
    - Threshold-based blocking (>7.6 bits/byte)
    - Catches obfuscated traffic that evades all other methods

## Development

### Run Tests

```bash
# Run all unit tests
make test

# Run with coverage
go test ./... -cover

# Run with verbose output
go test ./internal/blocker -v

# Run benchmarks
go test ./internal/blocker -bench=. -benchmem

# Run integration tests (tests full packet processing pipeline)
go test -tags=integration ./test/integration -v

# Run integration tests with Docker
cd test/integration && docker-compose up --build
```

### Test Coverage

The project includes comprehensive test coverage:

**Unit Tests:**
- **76%+** code coverage of blocker package
- **165+** test cases covering all detection methods
- **16** performance benchmarks

Unit test files:
- `analyzer_test.go` - Multi-layer packet analysis tests (13 test cases)
- `detectors_test.go` - Protocol detection tests (117 test cases)
  - MSE/PE encryption detection tests
  - LSD detection tests
  - Extended Protocol (BEP 10) tests
  - FAST Extension (BEP 6) tests
  - HTTP BitTorrent detection tests (WebSeed, Bitcomet, User-Agent)
  - Enhanced DHT detection tests (Suricata prefixes, node validation)
  - UDP tracker, uTP, DHT, SOCKS tests
- `config_test.go` - Configuration validation tests (10 test cases)
- `ipban_test.go` - IP banning mechanism tests (26 test cases)

**Integration Tests:**
- End-to-end packet processing pipeline tests
- Real-world traffic pattern simulation
- False positive rate testing (0% target)
- Performance benchmarking (10K+ packets)
- Multi-layer detection verification

See [test/integration/README.md](test/integration/README.md) for details.

**End-to-End Tests:**
- Real-world deployment simulation on NixOS
- Actual network traffic interception with nfqueue
- iptables/ipset integration testing
- Complete service lifecycle verification

See [test/e2e/README.md](test/e2e/README.md) for E2E testing details.

### Build

```bash
make build
```

### Run (Development)

```bash
make run
```

## Deployment

### NixOS

The project includes a complete NixOS module for production deployment with automatic setup:

**Using flakes (recommended):**

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    bittorrent-blocker.url = "github:spaiter/BitTorrentBlocker";
  };

  outputs = { self, nixpkgs, bittorrent-blocker }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        bittorrent-blocker.nixosModules.default
        {
          services.btblocker = {
            enable = true;
            interface = "eth0";           # Your main network interface
            entropyThreshold = 7.6;       # Encrypted traffic detection threshold
            minPayloadSize = 60;          # Minimum packet size for analysis
            ipsetName = "torrent_block";  # Name of ipset for banned IPs
            banDuration = 18000;          # Ban duration in seconds (5 hours)
            logLevel = "info";            # Log level: error, warn, info, debug
            firewallBackend = "nftables"; # Firewall backend: nftables or iptables
            cleanupOnStop = false;        # Keep banned IPs when service stops
          };
        }
      ];
    };
  };
}
```

**Using traditional configuration.nix:**

```nix
# /etc/nixos/configuration.nix
{ config, pkgs, ... }:
let
  bittorrent-blocker = builtins.fetchGit {
    url = "https://github.com/spaiter/BitTorrentBlocker";
    ref = "main";
  };
in
{
  imports = [
    "${bittorrent-blocker}/nix/module.nix"
  ];

  # Apply the overlay to make btblocker available
  nixpkgs.overlays = [
    (final: prev: {
      btblocker = (import bittorrent-blocker {
        system = prev.system;
      }).packages.${prev.system}.btblocker;
    })
  ];

  services.btblocker = {
    enable = true;
    interface = "eth0";
    logLevel = "info";
  };
}
```

**What gets configured automatically:**
- ✅ Binary installed from Cachix cache (instant installation)
- ✅ Systemd service with CAP_NET_ADMIN capability
- ✅ ipset created and destroyed on service start for clean state
- ✅ Firewall rules (nftables or iptables) for dropping banned IPs
- ✅ Automatic service restart on failure
- ✅ Kernel modules loaded (ip_set, ip_set_hash_ip)

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable` | bool | `false` | Enable the btblocker service |
| `interface` | string | `"eth0"` | Network interface to monitor |
| `entropyThreshold` | float | `7.6` | Entropy threshold for encrypted traffic detection |
| `minPayloadSize` | int | `60` | Minimum payload size for analysis |
| `ipsetName` | string | `"torrent_block"` | Name of ipset for banned IPs |
| `banDuration` | int | `18000` | Ban duration in seconds (default: 5 hours) |
| `logLevel` | enum | `"info"` | Log level: `error`, `warn`, `info`, `debug` |
| `firewallBackend` | enum | `"nftables"` | Firewall backend: `nftables` or `iptables` |
| `cleanupOnStop` | bool | `false` | Destroy ipset and clear banned IPs when service stops |

**Firewall Backend Selection:**
- `nftables` (default, recommended) - Modern Linux firewall
- `iptables` - Legacy firewall (use if nftables unavailable)

**Examples:**

```nix
# Example 1: Testing with short ban duration (30 seconds)
services.btblocker = {
  enable = true;
  interface = "awg0";
  banDuration = 30;
  logLevel = "debug";
};

# Example 2: Using iptables backend instead of nftables
services.btblocker = {
  enable = true;
  interface = "eth0";
  firewallBackend = "iptables";
};

# Example 3: Clean up banned IPs when service stops
services.btblocker = {
  enable = true;
  interface = "wg0";
  cleanupOnStop = true;  # Banned IPs cleared on service stop
};
```

**After configuration:**
```bash
# Rebuild your system
sudo nixos-rebuild switch

# Check service status
sudo systemctl status btblocker

# View logs
sudo journalctl -u btblocker -f

# Check banned IPs
sudo ipset list torrent_block
```

## Detection Accuracy

The blocker uses multiple complementary techniques to minimize false positives:
- **Whitelist**: Common ports excluded (HTTP, HTTPS, SSH, DNS, XMPP, DNS-over-TLS)
- **11-Layer Detection**: Ordered by specificity to reduce false positives
- **Conservative Thresholds**: Entropy threshold (7.6), minimum payload size (60 bytes)
- **Extensive Testing**: 165+ test cases covering edge cases and real-world patterns
- **Critical MSE/PE Detection**: Catches 70-80% of encrypted BitTorrent traffic
- **Multi-BEP Support**: Implements detection for BEPs 5, 6, 10, 11, 14, 19, 29
- **HTTP Protocol Coverage**: Detects WebSeed, Bitcomet, and client User-Agents
- **Suricata-Grade DHT Validation**: Binary node structure validation for enhanced accuracy

## Performance

Benchmark results (AMD Ryzen 7 9800X3D):

| Operation | Time | Allocations |
|-----------|------|-------------|
| BitTorrent detection | 4.1 ns/op | 0 allocs/op |
| UDP Tracker check | 2.4 ns/op | 0 allocs/op |
| HTTP traffic analysis | 565 ns/op | 0 allocs/op |
| Cached IP ban | 20.6 ns/op | 0 allocs/op |
| Entropy calculation | 926 ns/op | 0 allocs/op |

Features:
- Minimal CPU overhead using lazy packet parsing
- Efficient signature matching with byte slicing
- Zero allocations on critical paths
- Cached IP banning to avoid duplicate system calls
- Designed for high-throughput network environments

## License

MIT — see [LICENSE](LICENSE).

## Credits

This project implements BitTorrent detection techniques inspired by and learned from the following open-source projects:

- [nDPI](https://github.com/ntop/nDPI) (LGPLv3) - Deep packet inspection methodologies and protocol signatures
- [libtorrent](https://www.libtorrent.org/) (BSD-3-Clause) - BitTorrent protocol specifications and implementation details
- [Suricata](https://suricata.io/) (GPLv2) - IDS/IPS rules and detection patterns
- [Sing-box](https://github.com/SagerNet/sing-box) (GPLv3) - uTP protocol detection techniques

**Note:** This project is an independent implementation written from scratch in Go. No source code was copied from the above projects. We studied their detection approaches and reimplemented similar techniques in our own codebase. All detection logic is original work released under the MIT License.

## Legal & Responsible Use

### Intended Use

This tool is designed for **legitimate network administration and compliance purposes**:

✅ **Appropriate Uses:**
- Protecting your own VPS/home server from liability
- Enforcing organizational acceptable use policies
- Complying with local laws and ISP/datacenter terms of service
- Preventing accidental policy violations by users
- Managing network resources and preventing abuse
- Meeting regulatory compliance requirements

❌ **Inappropriate Uses:**
- Deploying on networks you don't own or manage
- Violating users' privacy or legal rights without proper authorization
- Circumventing legitimate network monitoring or legal intercept
- Using in jurisdictions where DPI tools are prohibited

### Disclaimers

1. **Authorization Required**: Only deploy this tool on infrastructure you own, manage, or have explicit authorization to control.

2. **User Notification**: In many jurisdictions, you must inform users that network traffic is being monitored and filtered. Check your local regulations.

3. **No Legal Advice**: This tool helps with technical compliance but does not constitute legal advice. Consult with legal counsel about your obligations.

4. **No Warranty**: This software is provided "as-is" without guarantees of detection accuracy. Some BitTorrent traffic may evade detection, and legitimate traffic may occasionally be blocked.

5. **Liability**: The authors and contributors are not responsible for:
   - Misuse of this tool
   - Legal issues arising from deployment
   - False positives or negatives in detection
   - Any damages resulting from use of this software

### Privacy Considerations

This tool performs **Deep Packet Inspection (DPI)** which analyzes network traffic content. When deploying:

- **Inform users** that traffic filtering is active
- **Document your policies** clearly in terms of service
- **Minimize data retention** - only log what's necessary for your compliance needs
- **Secure your logs** - treat detection logs as sensitive data
- **Respect privacy laws** - comply with GDPR, CCPA, and local privacy regulations

### Compliance Note

BitTorrent protocol itself is **not illegal** - it's a legitimate technology used for:
- Linux distribution downloads
- Game updates and patches
- Open-source software distribution
- Legal content sharing

This tool exists because **server operators** may face liability for copyrighted content transferred through their infrastructure, regardless of their knowledge or intent. The tool helps prevent such liability by blocking the protocol entirely.

### Support

For questions about deployment, legal compliance, or ethical use, please open an issue on GitHub. We're here to help responsible server administrators protect their infrastructure.
