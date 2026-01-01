# NixOS Deployment Guide

This guide explains how to deploy the BitTorrent Blocker on your NixOS server.

## Quick Start

### 1. Add the NixOS Module

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
    queueNum = 0;
    entropyThreshold = 7.6;
    ipsetName = "torrent_block";
    banDuration = 18000;  # 5 hours
    logLevel = "info";    # error, warn, info, or debug
    interfaces = [ "eth0" ];  # Your network interface(s)
  };

  # Kernel modules are automatically loaded by the module
}
```

### 2. Rebuild Your System

```bash
sudo nixos-rebuild switch
```

### 3. Verify It's Running

```bash
# Check service status
systemctl status btblocker.service

# View logs
journalctl -u btblocker -f

# Check banned IPs
ipset list torrent_block

# Check iptables rules
iptables -L -n -v
iptables -t mangle -L -n -v
```

## Configuration Options

### services.btblocker Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable` | bool | false | Enable the BitTorrent blocker service |
| `queueNum` | int | 0 | Netfilter queue number to use |
| `entropyThreshold` | float | 7.6 | Entropy threshold for encrypted traffic detection |
| `minPayloadSize` | int | 60 | Minimum payload size for entropy analysis (bytes) |
| `ipsetName` | string | "torrent_block" | Name of ipset for banned IPs |
| `banDuration` | int | 18000 | Ban duration in seconds (5 hours) |
| `logLevel` | string | "info" | Log level: error, warn, info, or debug |
| `interfaces` | list | ["eth0"] | Network interfaces to monitor |
| `whitelistPorts` | list | [22, 53, 80, 443, 853, 5222, 5269] | Ports to never block |

### Example: Custom Configuration

```nix
services.btblocker = {
  enable = true;

  # Use queue 1 instead of 0
  queueNum = 1;

  # More aggressive entropy threshold
  entropyThreshold = 7.0;

  # Monitor multiple interfaces
  interfaces = [ "eth0" "eth1" "wlan0" ];

  # Longer ban duration (24 hours)
  banDuration = 86400;

  # Enable debug logging
  logLevel = "debug";

  # Add custom whitelisted ports
  whitelistPorts = [ 22 53 80 443 853 3000 8080 ];
};
```

## Architecture

```
Internet
   ↓
[Network Interface: eth0]
   ↓
[iptables PREROUTING]
   ↓
[NFQUEUE (queue 0)]
   ↓
[btblocker Service]
   ├─→ Analyze packet
   ├─→ Decision: Block or Allow
   ├─→ If Block: Add IP to ipset
   └─→ Return verdict
   ↓
[iptables checks ipset]
   ├─→ If IP banned: DROP
   └─→ If not banned: ACCEPT
   ↓
[Continue routing]
```

## Testing Your Deployment

### 1. Run E2E Tests

```bash
# Clone the repository
git clone https://github.com/yourusername/BitTorrentBlocker
cd BitTorrentBlocker

# Run NixOS VM test
nix-build test/e2e/e2e.nix

# Or run manual test on your server
cd test/e2e
sudo ./run-e2e-test.sh
```

### 2. Manual Verification

#### Test BitTorrent Detection

```bash
# Send a test BitTorrent handshake (from another machine)
python3 <<EOF
import socket

handshake = bytearray([19]) + b'BitTorrent protocol' + b'\\x00'*8
handshake += b'12345678901234567890' + b'-TEST00-123456789012'

sock = socket.socket()
sock.connect(('YOUR_SERVER_IP', 6881))
sock.send(handshake)
sock.close()
EOF

# Check if IP was banned
ssh your-server "sudo ipset list torrent_block"
```

#### Monitor Blocked Traffic

```bash
# Watch logs in real-time
journalctl -u btblocker -f

# Check statistics
ipset list torrent_block | grep "Number of entries"
```

## Troubleshooting

### Service Won't Start

**Problem**: Service fails to start

**Solutions**:
```bash
# Check logs for errors
journalctl -u btblocker -n 50

# Verify kernel modules
lsmod | grep nfnetlink_queue

# Load module manually
sudo modprobe nfnetlink_queue

# Check if queue number is available
cat /proc/net/netfilter/nfnetlink_queue
```

### No Traffic Being Analyzed

**Problem**: Blocker running but not seeing traffic

**Solutions**:
```bash
# Verify iptables rules
sudo iptables -t mangle -L PREROUTING -n -v

# Check if packets are going to queue
cat /proc/net/netfilter/nfnetlink_queue

# Test with tcpdump
sudo tcpdump -i eth0 -n port 6881
```

### False Positives

**Problem**: Normal traffic being blocked

**Solutions**:
1. Enable debug logging to see why traffic is blocked:
   ```nix
   services.btblocker.logLevel = "debug";
   ```
   Then rebuild and watch logs:
   ```bash
   sudo nixos-rebuild switch
   journalctl -u btblocker -f
   ```
2. Increase `entropyThreshold` (default: 7.6 → 7.8 or 8.0)
3. Increase `minPayloadSize` (default: 60 → 100 or 200)
4. Add ports to `whitelistPorts`

### High CPU Usage

**Problem**: btblocker using too much CPU

**Solutions**:
1. Reduce traffic to queue (use more specific iptables rules)
2. Limit to specific ports/protocols:
   ```nix
   # In your configuration, add custom iptables rules instead
   networking.firewall.extraCommands = ''
     # Only queue BitTorrent-typical ports
     iptables -t mangle -A PREROUTING -p tcp --dport 6881:6889 -j NFQUEUE --queue-num 0
     iptables -t mangle -A PREROUTING -p udp --dport 6881:6889 -j NFQUEUE --queue-num 0
   '';
   ```

## Production Recommendations

### 1. Resource Limits

Add resource limits to the systemd service:

```nix
systemd.services.btblocker.serviceConfig = {
  CPUQuota = "50%";
  MemoryMax = "512M";
};
```

### 2. Monitoring

Set up monitoring with Prometheus/Grafana:

```nix
services.prometheus.exporters.node.enable = true;

# Monitor btblocker metrics
services.prometheus.scrapeConfigs = [
  {
    job_name = "btblocker";
    static_configs = [{
      targets = [ "localhost:9100" ];
    }];
  }
];
```

### 3. Logging

Configure log level based on your needs:

```nix
services.btblocker = {
  enable = true;

  # Set log level (error, warn, info, debug)
  logLevel = "warn";  # Production: less verbose
  # logLevel = "debug";  # Debugging: shows all traffic

  # View logs with:
  # journalctl -u btblocker -f
};
```

**Log Levels:**
- `error` - Only critical errors (minimal logging)
- `warn` - Warnings and errors
- `info` - General information (default, recommended for production)
- `debug` - Detailed packet analysis (shows blocked/allowed packets, use for troubleshooting)

### 4. Debug Mode for Troubleshooting

When investigating false positives or blocked traffic:

```bash
# Enable debug logging temporarily
sudo systemctl stop btblocker
sudo LOG_LEVEL=debug btblocker

# Or edit the NixOS configuration and rebuild:
services.btblocker.logLevel = "debug";

# Watch debug output
journalctl -u btblocker -f
```

With debug logging enabled, you'll see:
- Every packet analyzed
- Why packets were blocked (which detection method triggered)
- Allowed packets passing through
- IP ban operations

### 5. Backup Ban List

Periodically backup the ipset:

```nix
systemd.services.ipset-backup = {
  description = "Backup BitTorrent IP ban list";
  script = ''
    ${pkgs.ipset}/bin/ipset save torrent_block > /var/lib/btblocker/ipset-backup.txt
  '';
  serviceConfig.Type = "oneshot";
};

systemd.timers.ipset-backup = {
  wantedBy = [ "timers.target" ];
  timerConfig = {
    OnCalendar = "hourly";
    Persistent = true;
  };
};
```

## Integration with Firewall

### nftables (Recommended for Modern NixOS)

If using nftables instead of iptables:

```nix
networking.nftables = {
  enable = true;
  ruleset = ''
    table inet filter {
      set torrent_block {
        type ipv4_addr
        flags timeout
      }

      chain prerouting {
        type filter hook prerouting priority -150; policy accept;
        ip saddr @torrent_block drop
        queue num 0
      }
    }
  '';
};
```

## Performance Tuning

For high-traffic servers:

```nix
services.btblocker = {
  enable = true;

  # Use higher entropy threshold (less sensitive, better performance)
  entropyThreshold = 7.8;

  # Larger min payload size (skip small packets)
  minPayloadSize = 100;

  # Use multiple queues for parallel processing (requires code modification)
  queueNum = 0;
};

# Increase nfqueue buffer
boot.kernel.sysctl = {
  "net.netfilter.nf_conntrack_max" = 262144;
  "net.core.netdev_max_backlog" = 5000;
};
```

## Uninstalling

To remove the blocker:

```nix
# In configuration.nix, disable the service
services.btblocker.enable = false;
```

Then rebuild:

```bash
sudo nixos-rebuild switch

# Manually clean up ipset if needed
sudo ipset destroy torrent_block
```

## Support

- GitHub Issues: https://github.com/yourusername/BitTorrentBlocker/issues
- Documentation: https://github.com/yourusername/BitTorrentBlocker/tree/main/docs
- E2E Tests: https://github.com/yourusername/BitTorrentBlocker/tree/main/test/e2e
