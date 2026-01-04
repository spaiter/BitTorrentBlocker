# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

BitTorrent Blocker is a high-performance Go library and CLI tool for detecting and blocking BitTorrent traffic using Deep Packet Inspection (DPI). It combines detection techniques from nDPI, libtorrent, Suricata, and Sing-box.

Module path: `github.com/example/BitTorrentBlocker`

## Architecture

The project follows standard Go project structure with a clear separation between the CLI application and reusable library components:

### Directory Structure

```
cmd/btblocker/main.go      - CLI application entry point
internal/blocker/          - Core blocker library (internal = not importable by external projects)
  ├── blocker.go          - Main blocker service (orchestrates packet processing)
  ├── analyzer.go         - Packet analysis engine (coordinates detection methods)
  ├── detectors.go        - Protocol detection functions (actual DPI logic)
  ├── signatures.go       - Signature databases (protocol patterns, magic numbers)
  ├── logger.go           - Logging with level support
  └── config.go           - Configuration management
internal/xdp/              - XDP (eXpress Data Path) kernel-space packet filtering
  ├── loader.go           - XDP program loader and manager
  └── map.go              - eBPF map manager for IP blocklist
```

### Key Components

1. **Blocker** (`blocker.go`): Main service that:
   - Receives packets from NFQUEUE (inline packet filtering)
   - Parses packets (IP, TCP, UDP layers) with zero-copy optimization
   - Coordinates analysis and returns verdicts (ACCEPT/DROP)
   - Manages XDP filter for fast-path blocking of known IPs
   - Handles graceful shutdown

2. **Analyzer** (`analyzer.go`): Packet analysis engine that:
   - Applies multiple detection methods in sequence
   - Returns structured analysis results
   - Makes final block/allow decisions

3. **Detectors** (`detectors.go`): Individual detection functions:
   - `CheckSignatures()` - Byte pattern matching
   - `CheckUDPTrackerDeep()` - UDP tracker protocol validation
   - `CheckUTPRobust()` - uTP protocol detection
   - `CheckBencodeDHT()` - DHT structure validation
   - `CheckSOCKSConnection()` - SOCKS proxy detection
   - `UnwrapSOCKS5()` - SOCKS5 header removal
   - `ShannonEntropy()` - Encryption detection

4. **Signatures** (`signatures.go`): Protocol databases:
   - `BTSignatures` - Known BitTorrent byte patterns
   - `PeerIDPrefixes` - Client identification strings
   - `WhitelistPorts` - Ports to never block
   - Protocol constants (magic numbers, actions)

5. **XDP Filter** (`internal/xdp/`): Kernel-space fast-path filtering:
   - Loads eBPF programs into the Linux kernel
   - Manages IP blocklist via eBPF maps (with expiration tracking)
   - Drops packets from known malicious IPs at NIC level (10+ Gbps)
   - Optional optimization for NFQUEUE (reduces userspace overhead)
   - Supports generic, native, and offload XDP modes

## Detection Strategy

The blocker uses a multi-layered approach to minimize false positives:

1. **Whitelist filtering** - Skip analysis for known-good ports
2. **SOCKS unwrapping** - Remove proxy headers to see inner traffic
3. **Signature matching** - Fast pattern search for known protocols
4. **Protocol validation** - Structural checks (UDP tracker, uTP, DHT)
5. **Entropy analysis** - Detect fully encrypted traffic (last resort)

Each layer is independent and contributes to the final verdict.

## Development Commands

### Build
```bash
make build
# Or directly:
go build -o bin/btblocker ./cmd/btblocker
```

Builds the binary to `bin/btblocker`.

### Run
```bash
# 1. Setup iptables to redirect traffic to NFQUEUE
sudo iptables -I FORWARD -p tcp -j NFQUEUE --queue-num 0
sudo iptables -I FORWARD -p udp -j NFQUEUE --queue-num 0

# 2. Start blocker
sudo ./bin/btblocker  # Requires root for NFQUEUE and XDP access
```

**Important**: The blocker requires:
- Linux with netfilter NFQUEUE support
- Linux with XDP/eBPF support (kernel 4.18+, optional for fast-path)
- Root privileges or CAP_NET_ADMIN capability
- iptables/nftables rules to redirect traffic to NFQUEUE
- Network interfaces with XDP support (for fast-path optimization)

### Test
```bash
make test
# Or directly:
go test ./...
```

Runs all tests across all packages. To run tests for a specific package:
```bash
go test ./internal/blocker
```

## Dependencies

- `github.com/florianl/go-nfqueue/v2` - Netfilter NFQUEUE interface (inline packet verdicts)
- `github.com/google/gopacket` - Packet parsing (lazy decoding for performance)
- `github.com/cilium/ebpf` - eBPF/XDP program loading and map management

## Configuration

Default configuration in `config.go`:
- `QueueNum: 0` - NFQUEUE number to receive packets from iptables
- `Interfaces: []string{"eth0"}` - Network interface for XDP fast-path (optional)
- `BanDuration: 18000` - Ban duration in seconds (5 hours)
- `LogLevel: "info"` - Logging level (error, warn, info, debug)
- `XDPMode: "generic"` - XDP mode (generic for compatibility, native for performance)
- `CleanupInterval: 300` - XDP cleanup interval in seconds (5 minutes)

## Architecture

**Two-tier inline blocking system:**

1. **NFQUEUE (Tier 1)**: Inline DPI for first-packet detection
   - All packets queued for userspace analysis
   - Full DPI with 11 detection methods
   - Returns verdict: DROP (BitTorrent) or ACCEPT (normal)
   - Throughput: ~1-2 Gbps
   - Latency: ~1-5ms per packet

2. **XDP (Tier 2)**: Fast-path for known malicious IPs
   - Blocks at kernel level before NFQUEUE
   - Zero-copy, minimal overhead
   - Throughput: 10+ Gbps
   - Latency: ~10µs per packet

**Performance optimizations:**
- Uses lazy packet parsing (`gopacket.Lazy`, zero-copy)
- Efficient byte slice operations (no unnecessary copies)
- XDP fast-path eliminates NFQUEUE overhead for known IPs
- Early returns in detection functions
- Whitelist filtering before expensive analysis

## Go Version

The project uses Go 1.20 (see `go.mod`).

## Security Notes

This tool performs Deep Packet Inspection and blocks network traffic. It should only be deployed:
- On networks you own or have authorization to manage
- With proper legal and ethical considerations
- With understanding of its impact on users
