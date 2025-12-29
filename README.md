# BitTorrent Blocker

A high-performance Go library and CLI tool for detecting and blocking BitTorrent traffic using Deep Packet Inspection (DPI). Combines techniques from nDPI, libtorrent, Suricata, and Sing-box to provide comprehensive BitTorrent protocol detection.

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
- **Extensive Signature Database**: 80+ protocol signatures, 60+ client identifiers
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

## Prerequisites

- Go 1.20 or later
- Linux with netfilter/nfqueue support
- ipset utility (for IP banning)
- Root/CAP_NET_ADMIN privileges

## Installation

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
```

### Setup iptables Rules

Before running the blocker, configure iptables to send traffic to nfqueue:

```bash
# Create ipset for banned IPs
sudo ipset create torrent_block hash:ip timeout 18000

# Send traffic to nfqueue (adjust interface as needed)
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0

# Block IPs in the ipset
sudo iptables -I FORWARD -m set --match-set torrent_block src -j DROP
```

### Configuration

The blocker uses sensible defaults but can be customized:

```go
config := blocker.Config{
    QueueNum:         0,      // NFQUEUE number
    EntropyThreshold: 7.6,    // Entropy threshold for encrypted traffic
    MinPayloadSize:   60,     // Minimum payload size for analysis
    IPSetName:        "torrent_block",
    BanDuration:      "18000", // 5 hours in seconds
}
```

## How It Works

### Detection Methods

The blocker employs 10 complementary detection techniques, ordered by specificity:

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

7. **Signature Matching**: 80+ known BitTorrent protocol patterns
   - Protocol handshakes (`\x13BitTorrent protocol`)
   - PEX extension keys (`ut_pex`, `added`, `dropped`, `added6`)
   - DHT keys (ping, get_peers, announce_peer, find_node)
   - Extension protocol signatures (ut_metadata, ut_holepunch, yourip, reqq)
   - Magnet links, tracker URLs
   - BitTorrent v2 keys (piece layers, file tree)
   - Client PeerIDs: qBittorrent, Transmission, µTorrent, libtorrent, Deluge, etc.

8. **uTP Detection** (BEP 29): Micro Transport Protocol analysis
   - Version and type validation
   - Extension chain verification
   - Header structure validation

9. **DHT Analysis** (BEP 5): Structural bencode dictionary validation
   - Query/Response type checking (y:q, y:r)
   - Transaction ID presence
   - DHT-specific keys (nodes, values, token)

10. **Entropy Analysis**: Last-resort detection for fully encrypted traffic
    - Shannon entropy calculation
    - Threshold-based blocking (>7.6 bits/byte)
    - Catches obfuscated traffic that evades all other methods

## Development

### Run Tests

```bash
# Run all tests
make test

# Run with coverage
go test ./... -cover

# Run with verbose output
go test ./internal/blocker -v

# Run benchmarks
go test ./internal/blocker -bench=. -benchmem
```

### Test Coverage

The project includes comprehensive test coverage:

- **69.8%** code coverage of blocker package
- **113** test cases covering all detection methods
- **13** performance benchmarks

Test files:
- `analyzer_test.go` - Multi-layer packet analysis tests (10 test cases)
- `detectors_test.go` - Protocol detection tests (67 test cases)
  - MSE/PE encryption detection tests
  - LSD detection tests
  - Extended Protocol (BEP 10) tests
  - FAST Extension (BEP 6) tests
  - UDP tracker, uTP, DHT, SOCKS tests
- `config_test.go` - Configuration validation tests (10 test cases)
- `ipban_test.go` - IP banning mechanism tests (26 test cases)

### Build

```bash
make build
```

### Run (Development)

```bash
make run
```

## Detection Accuracy

The blocker uses multiple complementary techniques to minimize false positives:
- **Whitelist**: Common ports excluded (HTTP, HTTPS, SSH, DNS, XMPP, DNS-over-TLS)
- **10-Layer Detection**: Ordered by specificity to reduce false positives
- **Conservative Thresholds**: Entropy threshold (7.6), minimum payload size (60 bytes)
- **Extensive Testing**: 113 test cases covering edge cases and real-world patterns
- **Critical MSE/PE Detection**: Catches 70-80% of encrypted BitTorrent traffic
- **Multi-BEP Support**: Implements detection for BEPs 5, 6, 10, 11, 14, 29

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

Detection techniques based on:
- [nDPI](https://github.com/ntop/nDPI) - Network protocol detection
- [libtorrent](https://www.libtorrent.org/) - BitTorrent protocol implementation
- [Suricata](https://suricata.io/) - IDS/IPS rules
- [Sing-box](https://github.com/SagerNet/sing-box) - uTP detection

## Security Notice

This tool is intended for network administration and security purposes. Ensure you have proper authorization before deploying on any network. The authors are not responsible for misuse.
