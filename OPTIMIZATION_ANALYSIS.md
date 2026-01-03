# Detection Performance Optimization Analysis

Analysis of current detection performance and optimization opportunities.

## Current Performance Baseline

From benchmarks and test data:
- **CheckSignatures**: 31.87 ns/op (slowest commonly-hit detector)
- **CheckBitTorrentMessage**: 1.25 ns/op (fast but called late)
- **True-positive detection breakdown** (200 packets analyzed):
  - Signature Match: 72 detections (66.1%)
  - BitTorrent Message Structure: 37 detections (33.9%)

## Identified Optimization Opportunities

### 1. **Signature Checking Optimization** (HIGH IMPACT)

**Problem**: CheckSignatures iterates through 107 signatures linearly, taking 31.87 ns/op.

**Optimization Strategies**:

#### A. **Order Signatures by Hit Rate**
Most common signatures should be checked first for early exit:
- `"BitTorrent protocol"` - Most common (handshake)
- `"\x13BitTorrent protocol"` - With length prefix
- `"d1:ad2:id20:"` - DHT announce (very common)
- `"d1:rd2:id20:"` - DHT response (very common)

**Expected Improvement**: 20-40% faster for typical traffic

#### B. **Fast-Path for Common Patterns**
```go
// Check most common signatures first (before loop)
if bytes.Contains(payload, []byte("BitTorrent protocol")) {
    return true
}
if len(payload) >= 13 && payload[0] == 'd' && payload[1] == '1' {
    // Fast check for DHT patterns: d1:ad2:id20: or d1:rd2:id20:
    if payload[2] == ':' && (payload[3] == 'a' || payload[3] == 'r') {
        return true
    }
}
// Then check remaining signatures
```

**Expected Improvement**: 50-70% faster for DHT/handshake traffic

#### C. **Payload Length Pre-filtering**
Skip signatures longer than payload:
```go
for _, sig := range BTSignatures {
    if len(sig) > len(payload) {
        continue // Skip impossible matches
    }
    if bytes.Contains(payload, sig) {
        return true
    }
}
```

**Expected Improvement**: 5-10% faster

###  2. **Analyzer Pipeline Reordering** (MEDIUM IMPACT)

**Problem**: Current ordering is by individual detector speed, not by practical hit rate × speed.

**Current Order**:
1. CheckFASTExtension (0.38 ns/op, TCP only, rare)
2. CheckLSD (1.13 ns/op, UDP only, rare)
3. CheckUDPTrackerDeep (3.73 ns/op, UDP only, moderate)
4. CheckMSEEncryption (899 ns/op, rare but critical)
5. CheckBencodeDHT (2.81 ns/op, UDP, common)
6. CheckHTTPBitTorrent (7.17 ns/op, TCP only, moderate)
7. CheckSignatures (31.87 ns/op, **common - 66% hit rate!**)
8. CheckBitTorrentMessage (1.25 ns/op, TCP only, **common - 34% hit rate!**)

**Problem**: CheckBitTorrentMessage is very fast (1.25 ns/op) and has high hit rate (34%), but it's called AFTER the slow CheckSignatures (31.87 ns/op).

**Proposed Reorder for TCP**:
```
1. CheckFASTExtension (0.38 ns) - fastest
2. CheckBitTorrentMessage (1.25 ns) - fast + high hit rate ✅
3. CheckHTTPBitTorrent (7.17 ns) - moderate speed
4. CheckSignatures (31.87 ns) - slow but catches remaining traffic
5. CheckMSEEncryption (899 ns) - expensive, last resort
```

**Proposed Reorder for UDP**:
```
1. CheckLSD (1.13 ns) - fastest UDP check
2. CheckUTPRobust (1.89 ns) - fast
3. CheckBencodeDHT (2.81 ns) - fast + common for DHT
4. CheckUDPTrackerDeep (3.73 ns) - moderate
```

**Expected Improvement**: 15-25% faster for typical TCP traffic

### 3. **Early UDP/TCP Split** (LOW IMPACT, CLEAN CODE)

**Problem**: We check `!isUDP` condition 4 times in the pipeline.

**Optimization**: Split into two separate fast paths:
```go
if isUDP {
    // UDP-only checks
    if CheckLSD(...) { return ... }
    if CheckUTPRobust(...) { return ... }
    if CheckBencodeDHT(...) { return ... }
    if CheckUDPTrackerDeep(...) { return ... }
    return AnalysisResult{ShouldBlock: false}
}

// TCP-only checks
if CheckFASTExtension(...) { return ... }
if CheckBitTorrentMessage(...) { return ... }
if CheckHTTPBitTorrent(...) { return ... }
if CheckSignatures(...) { return ... }
if CheckMSEEncryption(...) { return ... }
```

**Benefits**:
- Better branch prediction
- Fewer conditional checks per packet
- More cache-friendly (smaller code paths)

**Expected Improvement**: 5-10% faster

### 4. **Signature Length Indexing** (ADVANCED, FUTURE)

**Concept**: Group signatures by length for faster rejection:
```go
var signaturesByLength = map[int][][]byte{
    23: {[]byte("\x13BitTorrent protocol")},
    19: {[]byte("BitTorrent protocol")},
    13: {[]byte("d1:ad2:id20:"), []byte("d1:rd2:id20:")},
    // ...
}
```

Check only signatures that could fit in the payload.

**Expected Improvement**: 20-30% faster for signature checking

## Proposed Implementation Plan

### Phase 1: Low-Hanging Fruit (Easy Wins)
1. ✅ Reorder signatures by hit rate (most common first)
2. ✅ Move CheckBitTorrentMessage earlier for TCP
3. ✅ Add fast-path for "BitTorrent protocol" string

**Expected Total Improvement**: 30-40% faster

### Phase 2: Structural Improvements
1. Split UDP/TCP into separate fast paths
2. Add payload length pre-filtering to CheckSignatures

**Expected Total Improvement**: 40-50% faster

### Phase 3: Advanced Optimizations (If Needed)
1. Implement signature length indexing
2. Profile-Guided Optimization (PGO) with Go 1.20+
3. Consider SIMD for multi-pattern matching

**Expected Total Improvement**: 60-70% faster

## Testing Requirements

All optimizations must:
- ✅ Pass all existing tests (no regression)
- ✅ Maintain 100% false-positive accuracy (416/416 protocols)
- ✅ Maintain true-positive detection rates (all scenarios)
- ✅ Show measurable improvement in benchmarks

## Benchmark Methodology

Before/after comparison:
```bash
# Baseline
go test -bench=BenchmarkAnalyzer -benchmem -benchtime=10s ./internal/blocker | tee baseline.txt

# After optimization
go test -bench=BenchmarkAnalyzer -benchmem -benchtime=10s ./internal/blocker | tee optimized.txt

# Compare
benchstat baseline.txt optimized.txt
```

## Risk Assessment

**Low Risk Optimizations**:
- Signature reordering (just changes loop order)
- Moving CheckBitTorrentMessage earlier (deterministic)
- Fast-path for common patterns (adds early exit)

**Medium Risk Optimizations**:
- UDP/TCP split (changes code structure significantly)
- Length-based filtering (adds complexity)

**High Risk Optimizations**:
- SIMD/assembly (platform-specific)
- Signature indexing (complex data structure)

## Expected Overall Improvement

**Conservative Estimate**: 30-40% faster (Phase 1 only)
**Optimistic Estimate**: 60-80% faster (All phases)

**Impact on Throughput**:
- Current: 135M packets/sec (typical BitTorrent)
- After Phase 1: ~180-190M packets/sec (+33-40%)
- After Phase 2: ~190-200M packets/sec (+40-50%)

On multi-core (8 cores):
- Current: 1.08 billion pkts/sec
- After optimization: 1.4-1.6 billion pkts/sec

## Next Steps

1. Implement Phase 1 optimizations
2. Run comprehensive benchmarks
3. Verify all tests pass
4. Commit if improvement >= 20%
5. Consider Phase 2 if needed
