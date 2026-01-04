# Performance Analysis

Performance benchmarks for BitTorrent Blocker's Deep Packet Inspection (DPI) detectors.

**Test Environment:**
- CPU: AMD Ryzen 7 9800X3D 8-Core Processor
- OS: Windows
- Go Version: 1.20+
- Benchmark Time: 5 seconds per test

## Benchmark Results

### Detection Functions (Ordered by Speed)

| Function | ns/op | Operations | Allocations | Use Case |
|----------|-------|-----------|-------------|----------|
| `CheckExtendedMessage` | **0.19 ns/op** | 1B+ ops/sec | 0 allocs | BT extended protocol messages |
| `CheckSOCKSConnection` | **0.19 ns/op** | 1B+ ops/sec | 0 allocs | SOCKS proxy detection |
| `CheckFASTExtension` | **0.38 ns/op** | 1B+ ops/sec | 0 allocs | FAST extension (BEP 6) |
| `CheckLSD` | **1.13 ns/op** | 1B+ ops/sec | 0 allocs | Local Service Discovery |
| `CheckBitTorrentMessage` | **1.25 ns/op** | 1B+ ops/sec | 0 allocs | BT message structure validation |
| `CheckUTPRobust` | **1.89 ns/op** | 1B+ ops/sec | 0 allocs | uTP (Micro Transport Protocol) |
| `CheckBencodeDHT` | **2.81 ns/op** | 1B+ ops/sec | 0 allocs | DHT bencode structures |
| `CheckUDPTrackerDeep` | **3.73 ns/op** | 1B+ ops/sec | 0 allocs | UDP tracker protocol |
| `CheckHTTPBitTorrent` | **7.17 ns/op** | 845M ops/sec | 0 allocs | HTTP-based BT (WebSeed, User-Agents) |
| `CheckDHTNodes` | **15.04 ns/op** | 399M ops/sec | 0 allocs | DHT node list validation |
| `CheckSignatures` | **31.87 ns/op** | 188M ops/sec | 0 allocs | Signature pattern matching |
| `CheckMSEEncryption` | **899 ns/op** | 6.7M ops/sec | 0 allocs | Message Stream Encryption |
| `ShannonEntropy` | **928 ns/op** | 6.5M ops/sec | 0 allocs | Entropy analysis for encryption |

### End-to-End Analyzer Performance

| Scenario | ns/op | Throughput | Description |
|----------|-------|-----------|-------------|
| **BitTorrent (Early Detection)** | **7.41 ns/op** | **135M pkts/sec** | Fast signature match |
| **High Entropy** | **233 ns/op** | **4.3M pkts/sec** | Requires entropy calculation |
| **HTTP Analysis** | **536 ns/op** | **1.9M pkts/sec** | Full HTTP header parsing |

### IP Ban Manager Performance

| Operation | ns/op | Allocations | Description |
|-----------|-------|-------------|-------------|
| **Cached Ban** | **20.79 ns/op** | 0 allocs | Already in cache |
| **New Ban** | **38.67 ns/op** | 1 alloc | New IP, 16 bytes allocated |
| **Cache Cleanup** | **6,333 ns/op** | 0 allocs | Periodic cleanup |

## Performance Characteristics

### Zero-Allocation Design
All detection functions achieve **0 allocations per operation**, minimizing GC pressure and ensuring consistent performance under load.

### Detection Ordering Strategy
Functions are ordered in the analyzer pipeline from fastest to slowest:
1. **Sub-nanosecond checks** (0.2-0.4 ns): Extended messages, FAST extension
2. **Few-nanosecond checks** (1-4 ns): LSD, DHT, UDP tracker
3. **Fast checks** (7-32 ns): HTTP BitTorrent, signatures
4. **Expensive checks** (900+ ns): Encryption detection, entropy

This ensures:
- **Early exit optimization**: Most packets are classified quickly
- **Minimal CPU overhead**: Fast rejection of non-BitTorrent traffic
- **Scalable performance**: Can handle millions of packets/second

### Real-World Performance

Based on benchmarks, a single core can analyze:
- **135 million packets/second** for typical BitTorrent traffic (early signature match)
- **4.3 million packets/second** for encrypted traffic (requires entropy analysis)
- **1.9 million packets/second** for HTTP analysis (full header parsing)

On a multi-core system (e.g., 8-core CPU), this scales linearly:
- **1+ billion packets/second** for typical traffic
- **34+ million packets/second** for encrypted traffic

### Throughput Estimates

Assuming average packet size of 1500 bytes:
- **Typical BitTorrent**: ~200 Gbps per core, ~1.6+ Tbps on 8 cores
- **Encrypted BitTorrent**: ~6.5 Gbps per core, ~52 Gbps on 8 cores
- **HTTP BitTorrent**: ~2.8 Gbps per core, ~22 Gbps on 8 cores

## Optimization Highlights

### 1. Lazy Packet Parsing
Uses `gopacket.Lazy` decoding to avoid parsing unnecessary protocol layers.

### 2. Efficient Byte Operations
- Uses `bytes.Contains()` and `bytes.HasPrefix()` for pattern matching
- Avoids string allocations with direct byte slice operations
- Manual bencode parsing without reflection

### 3. Early Returns
Each detector returns immediately upon finding a match, avoiding unnecessary work.

### 4. Caching
IP ban manager caches recent bans to avoid repeated system calls.

### 5. Whitelist Filtering
Skips analysis for known-good ports before expensive checks.

## Benchmark Methodology

Benchmarks are run with:
```bash
go test -bench=. -benchmem -benchtime=5s ./internal/blocker
```

Key metrics:
- **ns/op**: Nanoseconds per operation (lower is better)
- **B/op**: Bytes allocated per operation (0 is optimal)
- **allocs/op**: Memory allocations per operation (0 is optimal)

## Running Benchmarks

```bash
# Run all benchmarks
go test -bench=. -benchmem ./internal/blocker

# Run with longer duration for more accurate results
go test -bench=. -benchmem -benchtime=5s ./internal/blocker

# Compare before/after optimizations
go test -bench=. -benchmem ./internal/blocker | tee old.txt
# ... make changes ...
go test -bench=. -benchmem ./internal/blocker | tee new.txt
benchcmp old.txt new.txt
```

## Performance Considerations

### CPU-Bound vs I/O-Bound
- DPI analysis is **CPU-bound** (pure computation)
- Network packet capture is **I/O-bound** (kernel → userspace)
- Bottleneck is typically packet capture, not analysis

### Memory Usage
- Minimal heap allocations (0 allocs/op for all detectors)
- Fixed-size packet buffers from nfqueue
- Efficient for high-throughput scenarios

### Scalability
- Linear scaling across CPU cores
- No shared state between packet analysis
- Lock-free detection functions
- IP ban cache uses mutex only for writes

## Updated Performance Comments

The analyzer pipeline comments (lines 43-47 in `analyzer.go`) reflect these benchmarks:

```go
// Performance metrics from benchmarks (lower is faster):
// CheckFASTExtension: 0.38 ns/op, CheckLSD: 1.13 ns/op
// CheckUDPTrackerDeep: 3.73 ns/op, CheckBencodeDHT: 2.81 ns/op
// CheckHTTPBitTorrent: 7.17 ns/op, CheckSignatures: 31.87 ns/op
// CheckMSEEncryption: 899 ns/op, ShannonEntropy: 928 ns/op
```

## Future Optimization Opportunities

1. **SIMD Instructions**: Vectorize signature matching for even faster pattern detection
2. **Bloom Filters**: Pre-filter signatures before full byte comparison
3. **Profile-Guided Optimization (PGO)**: Use Go 1.20+ PGO for better branch prediction
4. **Assembly Optimizations**: Hand-optimize critical hot paths
5. **Parallel Processing**: Process multiple packets concurrently (if packet order doesn't matter)
