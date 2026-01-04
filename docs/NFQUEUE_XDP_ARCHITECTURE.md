# NFQUEUE + XDP Combined Architecture

## Overview

BitTorrentBlocker uses a **two-tier inline blocking architecture** that combines:
1. **NFQUEUE** - Inline DPI (Deep Packet Inspection) for first-packet detection
2. **XDP** - Kernel-space fast-path for blocking known IPs

This provides **true inline blocking** (no packets slip through) with **high performance** (10+ Gbps for known IPs).

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    Network Traffic                       │
│                   (eth0, wg0, etc.)                     │
└───────────────────────┬─────────────────────────────────┘
                        │
                   ┌────▼────┐
                   │   XDP   │ ◄─── Layer 1: Fast-path (kernel)
                   │ Filter  │
                   └─┬───┬───┘
                     │   │
              Known  │   │  Unknown
                IP   │   │     IP
                     │   │
                ┌────▼───▼───────┐
                │   DROP   PASS  │
                └──────────┬──────┘
                           │
                     ┌─────▼──────┐
                     │  iptables  │
                     │   NFQUEUE  │
                     └─────┬──────┘
                           │
                   ┌───────▼────────┐
                   │   btblocker    │ ◄─── Layer 2: DPI Analysis (userspace)
                   │  (DPI Engine)  │
                   └───┬────────┬───┘
                       │        │
                  Torrent   Normal
                Detected   Traffic
                       │        │
                  ┌────▼────┐   │
                  │  DROP   │   │
                  │  packet │   │
                  │ +       │   │
                  │ Add IP  │   │
                  │ to XDP  │   │
                  └─────────┘   │
                                │
                           ┌────▼────┐
                           │ ACCEPT  │
                           │ packet  │
                           └─────────┘
```

## How It Works

### First Packet (Unknown IP):
1. Packet arrives at network interface
2. **XDP checks blocklist** - IP not found, pass to network stack
3. Packet reaches **iptables**, redirected to NFQUEUE
4. **btblocker** receives packet in userspace
5. **DPI analysis** detects BitTorrent protocol
6. Packet is **DROPPED immediately** (inline verdict)
7. Source IP is **added to XDP map** for fast-path blocking

### Subsequent Packets (Known IP):
1. Packet arrives at network interface
2. **XDP checks blocklist** - IP found!
3. Packet is **DROPPED at kernel level** (zero latency, no userspace)
4. Never reaches iptables or btblocker

### Result:
- ✅ **First packet is blocked** (inline NFQUEUE verdict)
- ✅ **All future packets blocked at line rate** (XDP kernel-space)
- ✅ **No BitTorrent connections succeed**
- ✅ **Scales to 10+ Gbps** (XDP handles known IPs)

## Performance Characteristics

| Packet Type | Processing Path | Latency | Throughput |
|-------------|-----------------|---------|------------|
| **Unknown IP (first)** | XDP → NFQUEUE → DPI | ~1-5ms | ~1-2 Gbps |
| **Known IP (cached)** | XDP only | ~10µs | 10+ Gbps |
| **Normal traffic** | XDP → NFQUEUE → Accept | ~1-5ms | ~1-2 Gbps |

### Why This is Optimal:

1. **First-packet blocking** - NFQUEUE provides inline verdict, no connections succeed
2. **Scalability** - XDP handles 99% of blocked traffic at kernel level
3. **Learning system** - Once IP is detected, it's blocked at line rate forever
4. **Low false positives** - Full DPI analysis in userspace with complex detection

## Setup Requirements

### 1. iptables Rules

Redirect traffic to NFQUEUE for DPI analysis:

```bash
# Queue INPUT chain (traffic to this machine)
sudo iptables -I INPUT -p tcp -j NFQUEUE --queue-num 0
sudo iptables -I INPUT -p udp -j NFQUEUE --queue-num 0

# Queue FORWARD chain (traffic being routed through this machine)
sudo iptables -I FORWARD -p tcp -j NFQUEUE --queue-num 0
sudo iptables -I FORWARD -p udp -j NFQUEUE --queue-num 0
```

**Note**: These rules add ~1-5ms latency to ALL traffic. This is the cost of inline DPI.

### 2. Start btblocker

```bash
# Default configuration (NFQUEUE 0, XDP on eth0)
sudo ./bin/btblocker

# Custom NFQUEUE number
sudo QUEUE_NUM=5 ./bin/btblocker

# Custom XDP interface (for fast-path)
sudo INTERFACE=wg0 ./bin/btblocker

# Monitor mode (don't actually block, just log)
sudo MONITOR_ONLY=true ./bin/btblocker
```

### 3. Verify Setup

```bash
# Check iptables rules
sudo iptables -L -n -v | grep NFQUEUE

# Check XDP program is loaded
sudo ip link show eth0 | grep xdp

# Check btblocker logs
sudo journalctl -u btblocker -f
```

## Comparison with Other Architectures

| Architecture | First Packet | Scalability | Latency | Complexity |
|--------------|-------------|-------------|---------|------------|
| **libpcap only** | ❌ Always passes | Low (~1 Gbps) | Zero impact | Simple |
| **NFQUEUE only** | ✅ Blocked | Low (~1-2 Gbps) | ~1-5ms all traffic | Simple |
| **XDP only** | ❌ Passes (learning) | High (10+ Gbps) | ~10µs | Complex (eBPF) |
| **NFQUEUE + XDP** ✅ | ✅ Blocked | High (10+ Gbps) | ~1-5ms (until learned) | Moderate |

## Best Practices

### For VPN/VPS Providers (Router Mode):
```bash
# Queue only FORWARD chain (routed traffic)
sudo iptables -I FORWARD -p tcp -j NFQUEUE --queue-num 0
sudo iptables -I FORWARD -p udp -j NFQUEUE --queue-num 0

# Start blocker with WireGuard interface
sudo INTERFACE=wg0 ./bin/btblocker
```

### For High-Traffic Scenarios (>5 Gbps):
```bash
# Use native XDP mode for maximum performance
sudo INTERFACE=eth0 XDP_MODE=native ./bin/btblocker
```

### For Testing (No Blocking):
```bash
# Monitor mode - logs detections but accepts all packets
sudo MONITOR_ONLY=true ./bin/btblocker
```

## Troubleshooting

### "Failed to open NFQUEUE 0"
- **Cause**: No iptables rules redirecting traffic to NFQUEUE
- **Fix**: Add iptables rules (see Setup step 1)

### "Failed to initialize XDP filter"
- **Cause**: Kernel doesn't support XDP (< 4.18) or interface doesn't support XDP
- **Impact**: Still works, but without fast-path optimization
- **Fix**: Upgrade kernel or ignore (NFQUEUE still provides inline blocking)

### High CPU usage
- **Cause**: Lots of unknown IPs being analyzed (new connections)
- **Solution**: XDP fast-path will kick in after first detection, CPU will drop
- **Mitigation**: Use `XDP_MODE=native` for better performance

### Latency impact on normal traffic
- **Expected**: 1-5ms added latency for all traffic (NFQUEUE overhead)
- **Unavoidable**: This is the cost of inline DPI
- **Mitigation**: Once IPs are learned, they're blocked at XDP (no NFQUEUE overhead)

## Monitoring

### Check XDP blocklist size:
```bash
# View blocked IPs (requires bpftool)
sudo bpftool map dump name blocked_ips

# Count blocked IPs
sudo bpftool map dump name blocked_ips | grep -c "key:"
```

### Monitor NFQUEUE statistics:
```bash
# Check queue depth
cat /proc/net/netfilter/nfnetlink_queue

# Watch btblocker logs
sudo journalctl -u btblocker -f
```

### Performance metrics:
```bash
# Check packet drops (should be zero if queue is sized correctly)
cat /proc/net/netfilter/nfnetlink_queue | awk '{print "Queue:", $1, "Dropped:", $3}'
```

## Conclusion

The NFQUEUE + XDP architecture provides the **best of both worlds**:
- ✅ **True inline blocking** - No packets escape (NFQUEUE)
- ✅ **High performance** - Known IPs blocked at line rate (XDP)
- ✅ **Low false positives** - Full DPI analysis (userspace)
- ✅ **Scalable** - Handles 10+ Gbps after learning period

This is the recommended architecture for production deployments.
