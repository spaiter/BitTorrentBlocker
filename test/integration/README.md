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

## Requirements

- Go 1.20+
- Linux with netfilter/nfqueue support (for non-mocked tests)
- Docker (optional, for containerized tests)
- Root/CAP_NET_ADMIN privileges (for real nfqueue tests)
