# NixOS Deployment Guide (XDP Architecture)

Complete guide for deploying BitTorrent Blocker on NixOS using the official NixOS module with XDP (eXpress Data Path) kernel-space packet filtering.

## Prerequisites

- **Linux Kernel**: 4.18 or later (for XDP support)
- **NixOS**: 23.05 or later recommended
- **Architecture**: x86_64-linux or aarch64-linux

The module will automatically verify kernel compatibility at build time.

## Installation Methods

### Method 1: Using Flakes (Recommended)

**Step 1**: Create or edit `/etc/nixos/flake.nix`:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    btblocker.url = "github:spaiter/BitTorrentBlocker";
  };

  outputs = { nixpkgs, btblocker, ... }: {
    nixosConfigurations.yourhostname = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./configuration.nix
        btblocker.nixosModules.default
      ];
    };
  };
}
```

**Step 2**: Enable in `/etc/nixos/configuration.nix`:

```nix
{
  services.btblocker = {
    enable = true;
    interface = "eth0";  # Your network interface
    xdpMode = "generic"; # or "native" if your driver supports it
  };
}
```

**Step 3**: Deploy:

```bash
sudo nixos-rebuild switch --flake /etc/nixos#yourhostname
```

### Method 2: Direct Module Import

Add the module to your NixOS configuration:

```nix
# /etc/nixos/configuration.nix
{ config, pkgs, ... }:

{
  imports = [
    # ... your other imports
    /path/to/BitTorrentBlocker/nix/module.nix
  ];

  # Enable the blocker service
  services.btblocker = {
    enable = true;
    interface = "eth0";        # Your network interface (supports comma-separated list)
    xdpMode = "generic";       # XDP mode: "generic" or "native"
    banDuration = 18000;       # 5 hours in seconds
    cleanupInterval = 300;     # Cleanup every 5 minutes
    logLevel = "info";         # error, warn, info, or debug
  };
}
```

Rebuild your system:

```bash
sudo nixos-rebuild switch
```

## Verify Installation

```bash
# Check service status
systemctl status btblocker.service

# View logs
journalctl -u btblocker -f

# Check XDP program attachment (requires bpftool)
sudo bpftool net show

# Monitor blocked IPs (XDP uses eBPF maps)
# The blocker logs when IPs are added/removed from the XDP blocklist
```

## Configuration Options

### services.btblocker Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable` | bool | false | Enable the BitTorrent blocker service |
| `interface` | string | "eth0" | Network interface(s) to monitor (comma-separated list) |
| `xdpMode` | enum | "generic" | XDP mode: "generic" (compatible) or "native" (faster, requires driver support) |
| `banDuration` | int | 18000 | Ban duration in seconds (5 hours) |
| `cleanupInterval` | int | 300 | XDP map cleanup interval in seconds (5 minutes) |
| `logLevel` | enum | "info" | Log level: "error", "warn", "info", or "debug" |
| `detectionLogPath` | string | "" | Path to detection log file (empty = disabled) |
| `monitorOnly` | bool | false | If true, only log detections without banning |

### Example: Custom Configuration

```nix
services.btblocker = {
  enable = true;

  # Monitor multiple interfaces (XDP attaches to first one)
  interface = "eth0,eth1,wlan0";

  # Use native XDP mode for better performance
  # (requires network driver with XDP support)
  xdpMode = "native";

  # Longer ban duration (24 hours)
  banDuration = 86400;

  # More frequent cleanup (1 minute)
  cleanupInterval = 60;

  # Enable debug logging
  logLevel = "debug";

  # Enable detection logging for analysis
  detectionLogPath = "/var/log/btblocker/detections.log";
};
```

## Architecture

```
Internet
   ↓
[Network Interface: eth0]
   ↓
[XDP Program (eBPF)]  ← Kernel-space filtering (40M+ pps)
   ├─→ Check IP in XDP map
   ├─→ If banned: XDP_DROP (instant)
   └─→ If not banned: XDP_PASS
   ↓
[Userspace Blocker (libpcap)]
   ├─→ DPI Analysis (Deep Packet Inspection)
   ├─→ Decision: Block or Allow
   └─→ If Block: Add IP to XDP map
   ↓
[Continue normal packet processing]
```

**Key Advantages of XDP:**
- **40M+ packets/second** processing rate (per CPU core)
- **<1 microsecond** lookup time for banned IPs
- **Zero context switches** (kernel-space only)
- **No iptables/nftables overhead**
- **Automatic cleanup** of expired bans

## XDP Modes

### Generic Mode (Default)

```nix
services.btblocker.xdpMode = "generic";
```

- ✅ **Compatible with all network drivers**
- ✅ **Works on virtual interfaces** (Docker, VMs)
- ⚡ **Good performance** (~10M pps)
- 📦 **Use for maximum compatibility**

### Native Mode (Advanced)

```nix
services.btblocker.xdpMode = "native";
```

- ⚡ **Best performance** (~40M+ pps)
- ⚠️ **Requires driver support** (check with `ethtool -i eth0`)
- ✅ **Supported drivers**: Intel (ixgbe, i40e), Mellanox (mlx5), virtio_net
- 🚫 **Not supported**: Most USB NICs, some virtual interfaces

**Check driver support:**
```bash
# Check if your driver supports XDP
ethtool -i eth0 | grep driver

# List of drivers with XDP support:
# - ixgbe (Intel 10G)
# - i40e (Intel 40G)
# - mlx5 (Mellanox)
# - virtio_net (QEMU/KVM)
# - veth (Linux virtual Ethernet)
```

## Testing Your Deployment

### 1. Verify XDP Program Loading

```bash
# Check if XDP program is attached
sudo bpftool net show

# Expected output:
# eth0(2) driver id 12
#   xdp id 45
```

### 2. Monitor Logs

```bash
# Watch blocker logs
journalctl -u btblocker -f

# You should see:
# - "Initializing XDP filter on eth0 (mode: generic)"
# - "XDP filter initialized successfully"
# - "[DETECT]" messages when BitTorrent traffic is found
```

### 3. Test BitTorrent Detection

```bash
# From another machine, send a BitTorrent handshake
python3 <<EOF
import socket

handshake = bytearray([19]) + b'BitTorrent protocol' + b'\\x00'*8
handshake += b'12345678901234567890' + b'-TEST00-123456789012'

sock = socket.socket()
sock.connect(('YOUR_SERVER_IP', 6881))
sock.send(handshake)
sock.close()
EOF

# Check if IP was banned (watch logs)
journalctl -u btblocker -n 20
```

## Troubleshooting

### Service Won't Start

**Error**: "failed to initialize XDP filter"

**Solutions**:
```bash
# Check kernel version (need 4.18+)
uname -r

# Check if bpf filesystem is mounted
mount | grep bpf

# Check service logs
journalctl -u btblocker -n 50
```

### XDP Program Not Attaching

**Error**: "XDP requires Linux 4.18+"

**Solution**: Upgrade your kernel:
```nix
# In configuration.nix, use latest kernel
boot.kernelPackages = pkgs.linuxPackages_latest;
```

### XDP MEMLOCK Error

**Error**: "operation not permitted (MEMLOCK may be too low, consider rlimit.RemoveMemlock)"

**Full error message**:
```
Failed to initialize XDP filter: loading eBPF objects: field XdpBlocker:
program xdp_blocker: map blocked_ips: map create: operation not permitted
(MEMLOCK may be too low, consider rlimit.RemoveMemlock)
```

**Cause**: eBPF programs require unlimited memory locking to create kernel maps. The default systemd `RLIMIT_MEMLOCK` is too restrictive.

**Solution**: The NixOS module automatically sets `LimitMEMLOCK = "infinity"` in the systemd service (as of commit 318f805). If you're still seeing this error:

1. **Update to the latest module**:
   ```bash
   # Update flake inputs
   nix flake update bittorrent-blocker

   # Rebuild system
   sudo nixos-rebuild switch --flake .#yourhostname
   ```

2. **Verify the fix is applied**:
   ```bash
   # Check systemd service configuration
   systemctl show btblocker | grep LimitMEMLOCK
   # Should output: LimitMEMLOCK=infinity
   ```

3. **If using an older version** (before commit 318f805), manually add to your configuration:
   ```nix
   systemd.services.btblocker.serviceConfig = {
     LimitMEMLOCK = "infinity";
   };
   ```

### No Traffic Being Analyzed

**Problem**: Blocker running but not seeing traffic

**Solutions**:
```bash
# Verify XDP program is attached
sudo bpftool net show

# Check interface is correct
ip link show

# Enable debug logging
services.btblocker.logLevel = "debug";
```

### High CPU Usage

**Problem**: btblocker using too much CPU

**Solutions**:
1. **Use native XDP mode** if your driver supports it (10x faster)
2. **Increase cleanup interval** to reduce overhead:
   ```nix
   services.btblocker.cleanupInterval = 600; # 10 minutes
   ```
3. **Add resource limits**:
   ```nix
   systemd.services.btblocker.serviceConfig = {
     CPUQuota = "50%";
     MemoryMax = "512M";
   };
   ```

### False Positives

**Problem**: Normal traffic being blocked

**Solutions**:
1. Enable debug logging:
   ```nix
   services.btblocker.logLevel = "debug";
   ```
2. Enable detection logging for analysis:
   ```nix
   services.btblocker.detectionLogPath = "/var/log/btblocker/detections.log";
   ```
3. Use monitor-only mode for testing:
   ```nix
   services.btblocker.monitorOnly = true;
   ```

## Production Recommendations

### 1. Resource Limits

```nix
systemd.services.btblocker.serviceConfig = {
  CPUQuota = "50%";
  MemoryMax = "512M";
};
```

### 2. Logging Configuration

```nix
services.btblocker = {
  enable = true;
  logLevel = "warn";  # Production: less verbose

  # Optional: detailed detection logging
  detectionLogPath = "/var/log/btblocker/detections.log";
};

# Rotate logs
services.logrotate.settings.btblocker = {
  files = "/var/log/btblocker/*.log";
  rotate = 7;
  frequency = "daily";
  compress = true;
};
```

**Log Levels:**
- `error` - Only critical errors
- `warn` - Warnings and errors (recommended for production)
- `info` - General information (includes detections)
- `debug` - Detailed packet analysis (troubleshooting only)

### 3. Performance Tuning

For high-traffic servers:

```nix
services.btblocker = {
  enable = true;

  # Use native XDP if supported (10x performance boost)
  xdpMode = "native";

  # Shorter ban duration = smaller XDP map
  banDuration = 3600;  # 1 hour

  # Less frequent cleanup
  cleanupInterval = 600; # 10 minutes
};

# Kernel tuning for XDP
boot.kernel.sysctl = {
  "net.core.netdev_max_backlog" = 10000;
  "net.core.netdev_budget" = 600;
  "net.core.bpf_jit_enable" = 1;
};
```

### 4. Monitoring

```nix
# Monitor service health
systemd.services.btblocker-healthcheck = {
  description = "BTBlocker Health Check";
  script = ''
    if ! systemctl is-active --quiet btblocker; then
      echo "BTBlocker service is not running!"
      exit 1
    fi

    # Check if XDP program is attached
    if ! ${pkgs.bpftool}/bin/bpftool net show | grep -q xdp; then
      echo "XDP program not attached!"
      exit 1
    fi
  '';
  serviceConfig.Type = "oneshot";
};

systemd.timers.btblocker-healthcheck = {
  wantedBy = [ "timers.target" ];
  timerConfig = {
    OnCalendar = "minutely";
    Persistent = true;
  };
};
```

## Performance Comparison

| Metric | XDP-Only | Legacy (ipset/iptables) |
|--------|----------|-------------------------|
| Packet processing | 40M+ pps | ~1M pps |
| IP lookup time | <1 microsecond | ~10 microseconds |
| Context switches | Zero | Many (userspace ↔ kernel) |
| Dependencies | None | ipset, iptables |
| Complexity | Simple | Complex (firewall rules) |

## Uninstalling

```nix
# In configuration.nix, disable the service
services.btblocker.enable = false;
```

Then rebuild:

```bash
sudo nixos-rebuild switch

# XDP program is automatically detached when service stops
# No manual cleanup needed!
```

## Support

- GitHub Issues: https://github.com/spaiter/BitTorrentBlocker/issues
- Documentation: https://github.com/spaiter/BitTorrentBlocker/tree/main/docs
- XDP Documentation: https://github.com/spaiter/BitTorrentBlocker/blob/main/docs/TWO_TIER_ARCHITECTURE.md
