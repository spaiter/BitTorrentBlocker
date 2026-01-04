# Two-Tier Blocking Architecture

## Overview

The two-tier architecture separates packet filtering into two layers: a fast XDP-based "Muscle" layer in kernel space and a smart DPI-based "Brain" layer in user space. This design achieves 10+ Gbps throughput by handling known-bad traffic in the kernel while only sending unknown traffic to user space for expensive deep packet inspection.

## Problem Statement

The original single-tier architecture processes **every packet** through DPI in user space:

- **Current Performance**: ~4M packets/second (135M to 920M for simple detectors)
- **Bottleneck**: Context switches between kernel and user space via NFQUEUE
- **Limitation**: Cannot scale beyond ~1 Gbps on typical hardware

**Key Insight**: After the "Brain" identifies a BitTorrent peer IP, **all future packets** from that IP should be blocked without DPI. The current architecture re-analyzes every packet from known-bad IPs.

## Solution: Two-Tier Architecture

### Tier 1: XDP "Muscle" (Kernel Space)
- **Fast path** for known-bad IPs
- Blocks packets before they reach the network stack
- **40M+ packets/second per core**
- <1 microsecond latency

### Tier 2: DPI "Brain" (User Space)
- **Slow path** for unknown IPs
- Deep packet inspection via NFQUEUE
- Identifies BitTorrent traffic
- Updates XDP blocklist for future fast-path blocking

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        Network Interface                     │
└────────────────────────┬────────────────────────────────────┘
                         │ All packets
                         ↓
              ┌──────────────────────┐
              │   XDP Hook (Tier 1)  │ ← eBPF program in kernel
              │   "Muscle Layer"     │
              └──────────┬───────────┘
                         │
            ┌────────────┴────────────┐
            │                         │
     Known-Bad IP              Unknown IP
      (in blocklist)           (not in blocklist)
            │                         │
            ↓                         ↓
      ┌─────────┐            ┌────────────────┐
      │  DROP   │            │  PASS (→ NFQUEUE)  │
      │ (fast)  │            │  for DPI analysis   │
      └─────────┘            └────────┬───────────┘
                                      │
                                      ↓
                         ┌────────────────────────┐
                         │  NFQUEUE (Tier 2)      │
                         │  "Brain Layer"         │
                         │  - DPI Analysis        │
                         │  - Protocol Detection  │
                         └────────┬───────────────┘
                                  │
                     ┌────────────┴────────────┐
                     │                         │
              BitTorrent Traffic        Legitimate Traffic
                     │                         │
                     ↓                         ↓
           ┌─────────────────┐         ┌──────────┐
           │ Add IP to XDP   │         │  ACCEPT  │
           │ blocklist       │         │          │
           │ Return: DROP    │         └──────────┘
           └─────────────────┘
                     │
                     └──→ Future packets from this IP
                          blocked at XDP (Tier 1)
```

## Packet Flow

### Flow 1: Unknown IP (First Packet)
1. Packet arrives at network interface
2. XDP hook checks blocklist → **NOT FOUND**
3. Packet passes to network stack
4. iptables redirects to NFQUEUE
5. DPI Brain analyzes packet
6. If BitTorrent detected:
   - Add IP to XDP blocklist (with expiration time)
   - Return DROP verdict
7. If legitimate: Return ACCEPT verdict

### Flow 2: Known-Bad IP (Subsequent Packets)
1. Packet arrives at network interface
2. XDP hook checks blocklist → **FOUND**
3. Check if ban expired:
   - If expired: PASS to network stack (user-space cleanup will remove later)
   - If active: **DROP immediately** (no context switch, no DPI)
4. Packet never reaches user space

### Flow 3: Ban Expiration
1. User-space cleanup goroutine runs periodically (e.g., every 5 minutes)
2. Scans XDP map for expired entries
3. Removes expired IPs from blocklist
4. Next packet from that IP goes through Flow 1 again

## Implementation Components

### 1. XDP eBPF Program (`internal/xdp/blocker.c`)

**C program compiled to eBPF bytecode:**

```c
// Map: blocked_ips (key: IPv4 as u32, value: expiration timestamp as u64)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, __u64);
} blocked_ips;

SEC("xdp")
int xdp_blocker(struct xdp_md *ctx) {
    // Parse Ethernet + IP headers
    __u32 src_ip = parse_src_ip(ctx);

    // Lookup in blocklist
    __u64 *expires_at = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (expires_at && now < *expires_at) {
        return XDP_DROP;  // Fast path: drop blocked IP
    }

    return XDP_PASS;  // Unknown IP: pass to network stack
}
```

**Key Features:**
- Hash map with 100k capacity (configurable)
- IPv4 source address as key
- Expiration timestamp as value
- Sub-microsecond lookup time

### 2. XDP Loader (`internal/xdp/loader.go`)

**Responsibilities:**
- Load eBPF program into kernel
- Attach to network interface
- Manage lifecycle (load/unload)

**API:**
```go
filter, err := xdp.NewXDPFilter("eth0")
defer filter.Close()  // Detaches XDP program
```

### 3. IP Map Manager (`internal/xdp/map.go`)

**Responsibilities:**
- Add/remove IPs from XDP blocklist
- Track expiration times in user space
- Periodic cleanup of expired entries

**API:**
```go
mapMgr := filter.GetMapManager()

// Add IP (ban for 5 hours)
mapMgr.AddIP(net.ParseIP("1.2.3.4"), 5*time.Hour)

// Check if blocked
blocked, _ := mapMgr.IsBlocked(ip)

// Remove IP
mapMgr.RemoveIP(ip)

// Start periodic cleanup (every 5 minutes)
mapMgr.StartPeriodicCleanup(5 * time.Minute)

// Manual cleanup
removed, _ := mapMgr.CleanupExpired()
```

### 4. Integration with Blocker Service (`internal/blocker/blocker.go`)

**Changes Required:**

1. **Initialize XDP filter** on startup:
```go
type Blocker struct {
    // ... existing fields
    xdpFilter *xdp.Filter
}

func New(config Config) (*Blocker, error) {
    // ... existing code

    // Initialize XDP filter (fail fast if unsupported)
    xdpFilter, err := xdp.NewXDPFilter(config.Interfaces[0])
    if err != nil {
        return nil, fmt.Errorf("XDP init failed: %w", err)
    }

    // Start periodic cleanup
    xdpFilter.GetMapManager().StartPeriodicCleanup(5 * time.Minute)

    return &Blocker{
        // ... existing fields
        xdpFilter: xdpFilter,
    }, nil
}
```

2. **Update XDP map on GUILTY verdict**:
```go
func (b *Blocker) handleVerdict(verdict Verdict, srcIP net.IP) {
    if verdict == GUILTY {
        // Add to XDP blocklist (ban for configured duration)
        duration := time.Duration(b.config.BanDuration) * time.Second
        if err := b.xdpFilter.GetMapManager().AddIP(srcIP, duration); err != nil {
            log.Printf("Failed to add IP to XDP map: %v", err)
        }

        // Still maintain ipset for backward compatibility (optional)
        b.banIP(srcIP)
    }
}
```

3. **Clean up on shutdown**:
```go
func (b *Blocker) Close() error {
    if b.xdpFilter != nil {
        b.xdpFilter.Close()  // Detaches XDP, stops cleanup
    }
    // ... existing cleanup
}
```

## Performance Characteristics

### Single-Tier (Current)
| Metric | Value |
|--------|-------|
| Throughput | ~4M pps |
| Latency | ~250 µs per packet |
| Context Switches | Every packet |
| CPU Usage | High (DPI for all packets) |

### Two-Tier (New)
| Layer | Throughput | Latency | CPU Usage |
|-------|-----------|---------|-----------|
| XDP (Tier 1) | 40M+ pps | <1 µs | Very Low |
| DPI (Tier 2) | 4M pps | ~250 µs | Medium |

**Effective Throughput**: 10+ Gbps on 10 Gbps link (90%+ of packets blocked at XDP after warmup)

### Scaling Factors

**Warmup Period**: First few minutes as Brain identifies peers
- Initial: Most packets go through DPI (slow)
- After 5-10 minutes: 90%+ blocked at XDP (fast)

**Ban Duration**: Longer duration = better hit rate
- 5 hours (default): Good balance
- 24 hours: Maximum hit rate, risk of blocking reformed peers

**Blocklist Size**: Trade-off between memory and capacity
- 100k IPs: ~8 MB kernel memory
- 1M IPs: ~80 MB kernel memory

## Configuration

### New Config Options

```go
type Config struct {
    // ... existing fields

    // XDP configuration
    EnableXDP     bool   `env:"ENABLE_XDP" default:"true"`
    XDPMode       string `env:"XDP_MODE" default:"generic"`  // generic, native, offload
    CleanupInterval int  `env:"XDP_CLEANUP_INTERVAL" default:"300"`  // seconds
}
```

### NixOS Module Options

```nix
services.btblocker = {
  enable = true;
  interface = "eth0";

  # Two-tier configuration
  enableXDP = true;        # Enable XDP fast path (requires kernel 4.18+)
  xdpMode = "generic";     # generic (compatible) or native (faster)
  cleanupInterval = 300;   # Cleanup expired IPs every 5 minutes

  # Existing options
  banDuration = 18000;     # 5 hours
  logLevel = "info";
};
```

## Testing Strategy

### Unit Tests
- XDP map operations (add, remove, check, cleanup)
- Expiration logic
- Concurrent access safety

### Integration Tests
1. **XDP Initialization**: Verify XDP program loads on test interface
2. **Blocklist Updates**: Add IP → Verify in kernel map
3. **Packet Filtering**: Send packet from blocked IP → Verify DROP
4. **Expiration**: Add short-lived ban → Wait → Verify removed
5. **Cleanup**: Add many expired IPs → Trigger cleanup → Verify removed

### Performance Benchmarks
- XDP throughput (packets/sec)
- Map lookup latency
- Memory usage under load
- Cleanup performance (time to remove 10k expired IPs)

## Migration Path

### Phase 1: Feature Branch (Current)
- Implement XDP package
- Create integration layer
- Write tests and benchmarks
- Document architecture

### Phase 2: Optional Feature
- Merge to main with XDP disabled by default
- Add `ENABLE_XDP=true` environment variable
- Fail gracefully if XDP unavailable

### Phase 3: Default Enabled
- After 1-2 months of testing
- Make XDP default on Linux
- Keep fallback to NFQUEUE-only mode

### Phase 4: XDP Required
- Require kernel 4.18+ for production deployments
- Remove single-tier code path
- Maximum performance

## Limitations and Trade-offs

### Limitations
1. **Linux Only**: XDP requires Linux kernel 4.18+
2. **IPv4 Only**: Current implementation (IPv6 support planned)
3. **Warmup Period**: 5-10 minutes before full performance
4. **Memory Overhead**: ~8 MB per 100k blocked IPs

### Trade-offs
1. **Complexity vs Performance**: More complex code for 10× performance
2. **Generic vs Native Mode**:
   - Generic: Compatible with all drivers (20-30M pps)
   - Native: Faster but requires driver support (40-60M pps)
3. **Ban Duration vs False Positives**: Longer bans = better hit rate but higher risk if false positive

## Security Considerations

1. **eBPF Safety**: Kernel verifies eBPF programs before loading (no kernel crashes)
2. **Map Size Limits**: 100k capacity prevents memory exhaustion
3. **Expiration Required**: All entries have expiration (no permanent bans)
4. **Fail-Safe**: XDP failure falls back to NFQUEUE-only mode

## Future Enhancements

### Short-term (v1.0)
- [x] XDP blocklist with expiration
- [x] Periodic cleanup
- [x] Integration with DPI Brain
- [ ] NixOS module updates
- [ ] Performance benchmarks

### Medium-term (v2.0)
- [ ] IPv6 support
- [ ] Native XDP mode for supported drivers
- [ ] Per-IP statistics (packet count, byte count)
- [ ] Dynamic map sizing based on available memory

### Long-term (v3.0)
- [ ] XDP allowlist (bypass DPI for known-good IPs)
- [ ] eBPF-based DPI (move some detectors to kernel)
- [ ] Multi-queue support (per-CPU XDP maps)
- [ ] Hardware offload for supported NICs (100+ Gbps)

## References

- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [cilium/ebpf Documentation](https://pkg.go.dev/github.com/cilium/ebpf)
- [Linux XDP Documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [eBPF for Packet Processing](https://www.kernel.org/doc/html/latest/bpf/index.html)

---

**Status**: Implementation in progress on `feature/two-tier-blocking` branch
**Target Release**: v0.17.0
**Performance Goal**: 10+ Gbps on 10 Gbps link (10× improvement)
