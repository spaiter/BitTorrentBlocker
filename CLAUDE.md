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
  ├── ipban.go           - IP banning with caching (integrates with Linux ipset)
  └── config.go          - Configuration management
```

### Key Components

1. **Blocker** (`blocker.go`): Main service that:
   - Manages nfqueue connection
   - Parses packets (IP, TCP, UDP layers)
   - Coordinates analysis and verdict application
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

5. **IPBanManager** (`ipban.go`): Manages IP blocking:
   - Caches recent bans to avoid duplicate ipset calls
   - Integrates with Linux ipset for persistent blocking

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
sudo ./bin/btblocker  # Requires root for nfqueue access
```

**Important**: The blocker requires:
- Linux with netfilter/nfqueue support
- Root privileges or CAP_NET_ADMIN capability
- iptables rules to redirect traffic to nfqueue
- ipset utility for IP banning

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

- `github.com/florianl/go-nfqueue` - Netfilter queue interface
- `github.com/google/gopacket` - Packet parsing (lazy decoding for performance)

## Configuration

Default configuration in `config.go`:
- `QueueNum: 0` - NFQUEUE number to listen on
- `EntropyThreshold: 7.6` - Shannon entropy threshold for encrypted traffic
- `MinPayloadSize: 60` - Minimum payload size for entropy analysis
- `IPSetName: "torrent_block"` - ipset name for banned IPs
- `BanDuration: "18000"` - 5 hours ban duration (seconds)

## Performance Considerations

- Uses lazy packet parsing (`gopacket.Lazy`) to avoid unnecessary work
- Efficient byte slice operations (no unnecessary copies)
- Cached IP banning to avoid repeated system calls
- Early returns in detection functions
- Whitelist filtering before expensive analysis

## Go Version

The project uses Go 1.20 (see `go.mod`).

## Security Notes

This tool performs Deep Packet Inspection and blocks network traffic. It should only be deployed:
- On networks you own or have authorization to manage
- With proper legal and ethical considerations
- With understanding of its impact on users
