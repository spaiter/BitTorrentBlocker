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
   - Monitors network interfaces using libpcap
   - Parses packets (IP, TCP, UDP layers)
   - Coordinates analysis and verdict application
   - Manages XDP filter for kernel-space blocking
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

5. **XDP Filter** (`internal/xdp/`): Kernel-space packet filtering:
   - Loads eBPF programs into the Linux kernel
   - Manages IP blocklist via eBPF maps
   - Provides high-performance packet dropping at NIC level
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
make run
# Or:
sudo ./bin/btblocker  # Requires root for libpcap and XDP access
```

**Important**: The blocker requires:
- Linux with XDP/eBPF support (kernel 4.18+)
- Root privileges or CAP_NET_ADMIN capability
- libpcap for packet capture
- Network interfaces with XDP support

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

- `github.com/google/gopacket` - Packet parsing (lazy decoding for performance)
- `github.com/cilium/ebpf` - eBPF/XDP program loading and map management

## Configuration

Default configuration in `config.go`:
- `Interfaces: []string{"eth0"}` - Network interfaces to monitor
- `BanDuration: 18000` - Ban duration in seconds (5 hours)
- `LogLevel: "info"` - Logging level (error, warn, info, debug)
- `XDPMode: "generic"` - XDP mode (generic for compatibility, native for performance)
- `CleanupInterval: 300` - XDP cleanup interval in seconds (5 minutes)

## Performance Considerations

- Uses lazy packet parsing (`gopacket.Lazy`) to avoid unnecessary work
- Efficient byte slice operations (no unnecessary copies)
- XDP kernel-space filtering for high-performance packet dropping
- Early returns in detection functions
- Whitelist filtering before expensive analysis
- Supports 10+ Gbps throughput with XDP native mode

## Go Version

The project uses Go 1.20 (see `go.mod`).

## Security Notes

This tool performs Deep Packet Inspection and blocks network traffic. It should only be deployed:
- On networks you own or have authorization to manage
- With proper legal and ethical considerations
- With understanding of its impact on users
