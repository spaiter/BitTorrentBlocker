# Integration Tests

This directory contains integration tests for the BitTorrent Blocker that test the full packet processing pipeline with real network traffic patterns.

## Test Structure

- `integration_test.go` - Main integration test suite
- `docker-compose.yml` - Docker environment for tests (if needed)
- `testdata/` - Sample packet captures and test data

## Running Integration Tests

### Without Docker (Local)
```bash
# Run integration tests (requires root/admin for nfqueue)
go test -tags=integration ./test/integration -v

# Run with coverage
go test -tags=integration ./test/integration -v -coverprofile=coverage-integration.out
```

### With Docker
```bash
# Build and run test environment
docker-compose up --build

# Run tests in container
docker-compose run tests
```

## Test Coverage

Integration tests verify:
1. **End-to-End Packet Processing**: Full pipeline from packet capture to verdict
2. **Multi-Protocol Detection**: Real BitTorrent traffic patterns
3. **Performance**: Throughput and latency under load
4. **IP Banning**: Integration with ipset
5. **False Positive Rate**: Normal traffic should pass through
6. **Detection Logging**: Detailed packet logging for false positive analysis
7. **Monitor-Only Mode**: Detection without IP banning
8. **Combined Features**: Detection logging + monitor mode together
9. **nDPI Validation**: Real-world BitTorrent pcap files from nDPI project
   - Standard BitTorrent TCP traffic (24 flows)
   - BitTorrent with missing TCP handshake packets
   - BitTorrent over uTP (UDP-based protocol)
   - DHT peer searches
   - BitTorrent over TLS (encrypted)

## Requirements

- Go 1.20+
- Linux with netfilter/nfqueue support (for non-mocked tests)
- Docker (optional, for containerized tests)
- Root/CAP_NET_ADMIN privileges (for real nfqueue tests)

---

## XDP Integration Tests

The `xdp_test.go` file contains dedicated integration tests for the XDP (eXpress Data Path) kernel-space packet filtering layer.

### XDP Test Coverage

XDP tests validate the two-tier blocking architecture's kernel layer:

1. **XDP Filter Lifecycle** (`TestXDPFilterLifecycle`)
   - eBPF program loading and attachment
   - Resource cleanup and detachment

2. **IP Map Operations** (`TestXDPMapOperations`)
   - Add IP to blocklist
   - Check if IP is blocked
   - Remove IP from blocklist

3. **Multiple IPs** (`TestXDPMultipleIPs`)
   - Simultaneous blocking of 5 IPs
   - Bulk verification and removal

4. **Expiration Handling** (`TestXDPExpiration`)
   - Short-duration bans (2 seconds)
   - Manual cleanup of expired entries

5. **Periodic Cleanup** (`TestXDPPeriodicCleanup`)
   - Automatic background cleanup (1-second interval)
   - Goroutine lifecycle management

6. **IPv4 Validation** (`TestXDPIPv4Only`)
   - IPv6 rejection (XDP currently IPv4-only)

7. **Large-Scale Operations** (`TestXDPLargeScale`)
   - Stress test with 1000 IPs
   - Performance measurement (IPs/sec)
   - Skipped in `-short` mode

8. **Concurrent Access** (`TestXDPConcurrentOperations`)
   - 10 goroutines with 100 operations each
   - Thread-safety validation

9. **Interface Validation** (`TestXDPInterfaceValidation`)
   - Error handling for invalid interfaces

### Running XDP Tests

#### Quick Start (Docker - Any Platform)

```bash
# From project root
make test-xdp-docker
```

This builds a Linux container and runs XDP tests with required privileges.

#### Native Linux

```bash
# Run XDP integration tests (requires root)
sudo go test -v -tags "linux,integration" -timeout 5m ./test/integration/...

# Run specific XDP test
sudo go test -v -tags "linux,integration" -run TestXDPFilterLifecycle ./test/integration/...

# Skip slow large-scale tests
sudo go test -v -tags "linux,integration" -short ./test/integration/...
```

### XDP Test Requirements

- **Platform**: Linux kernel 4.18+ with XDP support
- **Privileges**: Root or CAP_NET_ADMIN (for eBPF program loading)
- **Build Tags**: `linux` and `integration` (automatically enforced)
- **Docker**: `--privileged` and `--network host` flags required

### Why Separate XDP Tests?

XDP tests are isolated because they:
1. Require kernel-level privileges (eBPF program loading)
2. Only work on Linux (XDP is Linux-specific)
3. Test kernel-space functionality (different from user-space DPI)
4. Need network interface access (loopback `lo` used for testing)

### Performance Expectations

Based on XDP benchmarks:
- **IP Add**: ~1000 IPs/second
- **IP Lookup**: <1 microsecond per packet
- **Cleanup**: ~10,000 IPs/second
- **Throughput**: 40M+ packets/second (per CPU core)

The `TestXDPLargeScale` test measures actual performance on your hardware.

### CI/CD Integration

Add to GitHub Actions:

```yaml
- name: Run XDP Integration Tests
  run: make test-xdp-docker
```

Standard GitHub runners support Docker with privileged mode - no special configuration needed!

### Related Documentation

- [internal/xdp/README.md](../../internal/xdp/README.md) - XDP package overview
- [internal/xdp/BUILD_NOTES.md](../../internal/xdp/BUILD_NOTES.md) - eBPF build instructions
- [Dockerfile.xdp-test](../../Dockerfile.xdp-test) - Test container definition
