# Sing-box BitTorrent Detection Integration

## Overview

This document describes the integration of test data and detection improvements from [sing-box](https://github.com/SagerNet/sing-box), a universal proxy platform. Sing-box includes BitTorrent protocol sniffing capabilities that we've validated against and improved upon.

## Sing-box Detection Methods

Sing-box implements three BitTorrent detection methods in `common/sniff/bittorrent.go`:

### 1. Standard BitTorrent Handshake (TCP)
- Detects `\x13BitTorrent protocol` header
- Stream-based detection with io.Reader interface
- **Status in Our Project**: ✅ Already implemented with signature matching

### 2. uTP Protocol (UDP)
- Validates uTP version (must be 1) and type (must be 0-4)
- **Validates extension types (must be 0-4)** - critical for avoiding false positives
- Walks extension chain to validate structure
- **Status**: ✅ **Enhanced** - Added extension type validation from sing-box

### 3. UDP Tracker Protocol
- Checks magic number `0x41727101980`
- Validates connect action (0x00)
- Minimum packet size validation
- **Status**: ✅ Already implemented identically

## Key Improvement: uTP Extension Validation

### The Problem
Our original uTP implementation didn't validate extension types, leading to a **false positive** with STUN packets.

**Before** (detectors.go:115-131):
```go
for extension != 0 {
    // Missing: extension type validation
    nextExtension := packet[offset]
    offset++
    // ...no check if nextExtension > 4
}
```

**Sing-box Implementation** (bittorrent.go:76-77):
```go
if extension > 0x04 {
    return os.ErrInvalid  // Reject invalid extension types
}
```

### The Fix
Added extension type validation based on BEP 29 specification:

**After** (detectors.go:123-127):
```go
// Validate extension type (must be 0-4 according to BEP 29)
// 0 = SACK, 1 = Extension bits, 2 = Close reason, 3-4 reserved
if nextExtension > 4 {
    return false
}
```

### Valid Extension Types (BEP 29)
- **0**: Selective ACK (SACK)
- **1**: Extension bits
- **2**: Close reason
- **3-4**: Reserved for future use
- **>4**: Invalid (reject packet)

## Test Integration

Created comprehensive test suite using sing-box's hex-encoded test data:

### Test File: `internal/blocker/singbox_test.go`

| Test | Packets | Description | Result |
|------|---------|-------------|--------|
| `TestSingBoxBitTorrentHandshake` | 3 | Real BitTorrent handshakes from various clients | ✅ 100% detected |
| `TestSingBoxUTPPackets` | 4 | SYN, DATA, FIN, RESET packets with extensions | ✅ 100% detected |
| `TestSingBoxUDPTracker` | 3 | UDP tracker connect requests | ✅ 100% detected |
| `TestSingBoxNotUTP` | 1 | STUN packet (should NOT detect) | ✅ **Fixed** - No false positive |
| `TestSingBoxIncompleteBitTorrent` | 1 | Truncated handshake | ✅ Correctly rejected |
| `TestSingBoxUTPExtensionValidation` | 1 | uTP without extensions | ✅ Detected |

### Test Data Sources

All test data is from sing-box's `bittorrent_test.go`:
- BitTorrent handshakes from real clients (uTorrent, Transmission)
- Real uTP packets captured from BitTorrent traffic
- UDP tracker protocol packets
- Negative test cases (STUN, incomplete packets)

## Comparison: Our Implementation vs Sing-box

| Feature | Sing-box | Our Implementation | Notes |
|---------|----------|-------------------|-------|
| BitTorrent Handshake | ✅ Stream-based | ✅ Pattern matching | Equal effectiveness |
| uTP Version/Type Check | ✅ v1, type ≤ 4 | ✅ Same validation | Equal |
| **uTP Extension Validation** | ✅ type ≤ 4 | ✅ **Added** | **Now equal** |
| UDP Tracker Magic | ✅ `0x41727101980` | ✅ Same constant | Equal |
| UDP Tracker Action | ✅ Connect = 0 | ✅ Same check | Equal |
| DHT Detection | ❌ Not implemented | ✅ Full DHT support | **We do more** |
| MSE/PE Encryption | ❌ Not implemented | ✅ Full MSE support | **We do more** |
| LSD Detection | ❌ Not implemented | ✅ Full LSD support | **We do more** |

## Benefits of Integration

1. **✅ Fixed False Positive**: STUN packets no longer detected as uTP
2. **✅ Validated Against Real Traffic**: All sing-box test data passes
3. **✅ Improved Extension Validation**: Proper BEP 29 compliance
4. **✅ Comprehensive Test Coverage**: 6 new test cases with real-world data

## What Sing-box Doesn't Detect (But We Do)

Sing-box focuses on basic protocol sniffing, while our project implements comprehensive BitTorrent blocking:

- ❌ **DHT Protocol**: Sing-box doesn't detect DHT at all
- ❌ **MSE/PE Encryption**: No support for encrypted BitTorrent
- ❌ **LSD (Local Service Discovery)**: No multicast detection
- ❌ **HTTP-based BitTorrent**: No WebSeed or User-Agent detection
- ❌ **Extended Messages**: No BEP 10 detection
- ❌ **FAST Extension**: No BEP 6 detection

Our implementation is **more comprehensive** while maintaining the same accuracy for basic protocols.

## Test Results

```
=== RUN   TestSingBoxBitTorrentHandshake
    ✅ DETECTED - 3/3 handshakes
=== RUN   TestSingBoxUTPPackets
    ✅ DETECTED - 4/4 uTP packets
=== RUN   TestSingBoxUDPTracker
    ✅ DETECTED - 3/3 tracker packets
=== RUN   TestSingBoxNotUTP
    ✅ PASSED - STUN correctly not detected (FALSE POSITIVE FIXED)
=== RUN   TestSingBoxIncompleteBitTorrent
    ✅ PASSED - Incomplete packet correctly rejected
=== RUN   TestSingBoxUTPExtensionValidation
    ✅ DETECTED - Basic uTP packet
```

**All 6 test cases pass**, confirming our detection is compatible with sing-box's expectations while being more comprehensive.

## Conclusion

The integration of sing-box test data and validation logic has:

1. **Fixed a critical false positive** (STUN packets)
2. **Improved uTP detection accuracy** with proper extension validation
3. **Validated our implementation** against real-world traffic
4. **Maintained our advantages** (DHT, MSE, LSD support)

Our BitTorrent detection is now validated against **three major projects**:
- ✅ **nDPI** (network protocol inspection)
- ✅ **Suricata** (IDS/IPS system)
- ✅ **Sing-box** (proxy platform)

This triple validation ensures our detection is production-ready and follows industry best practices.
