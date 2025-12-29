# BitTorrent Blocker

A high-performance Go library and CLI tool for detecting and blocking BitTorrent traffic using Deep Packet Inspection (DPI). Combines techniques from nDPI, libtorrent, Suricata, and Sing-box to provide comprehensive BitTorrent protocol detection.

## Features

- **Multi-Protocol Detection**: Identifies BitTorrent traffic over TCP and UDP
- **Deep Packet Inspection**: Uses signature-based and behavioral analysis
- **Protocol Coverage**:
  - Standard BitTorrent handshakes
  - UDP tracker protocol (Connect/Announce/Scrape)
  - DHT (Distributed Hash Table)
  - PEX (Peer Exchange)
  - uTP (Micro Transport Protocol)
  - Encrypted/obfuscated traffic via entropy analysis
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
git clone https://github.com/example/BitTorrentBlocker
cd BitTorrentBlocker

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

1. **Signature Matching**: Searches for known BitTorrent protocol strings
   - Protocol handshakes (`\x13BitTorrent protocol`)
   - PEX extension keys (`ut_pex`, `added`, `dropped`)
   - DHT bencode structures
   - Client PeerIDs (`-qB`, `-TR`, `-UT`, `-LT`)

2. **UDP Tracker Protocol**: Validates tracker packet structure
   - Magic protocol ID (0x41727101980)
   - Action types (Connect/Announce/Scrape)
   - Packet size validation

3. **uTP Detection**: Analyzes Micro Transport Protocol headers
   - Version and type validation
   - Extension chain verification

4. **DHT Analysis**: Structural bencode dictionary validation
   - Query/Response type checking
   - Key presence validation

5. **Entropy Analysis**: Detects encrypted traffic
   - Shannon entropy calculation
   - Threshold-based blocking (>7.6 bits/byte)

6. **SOCKS5 Unwrapping**: Removes proxy headers to inspect inner traffic

## Development

### Run Tests

```bash
make test
```

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
- Whitelist for common services (HTTP, HTTPS, SSH, DNS)
- Multiple detection layers (signature + behavioral + entropy)
- Conservative thresholds tuned for production use

## Performance

- Minimal CPU overhead using lazy packet parsing
- Efficient signature matching with byte slicing
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
