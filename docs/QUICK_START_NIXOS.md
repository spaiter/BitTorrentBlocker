# Quick Start Guide for NixOS

This is a quick reference for deploying BitTorrent Blocker on your NixOS server.

## TL;DR - Fastest Way to Get Started

```bash
# On your NixOS server, add to /etc/nixos/flake.nix:
nix flake init

# Then edit to add btblocker input
```

## Option 1: Using Flake (Recommended)

### Step 1: Create `/etc/nixos/flake.nix`

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    btblocker.url = "github:spaiter/BitTorrentBlocker";
  };

  outputs = { self, nixpkgs, btblocker }: {
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

### Step 2: Edit `/etc/nixos/configuration.nix`

```nix
{ config, pkgs, ... }:

{
  # Enable BitTorrent blocker
  services.btblocker = {
    enable = true;
    interface = "eth0";  # Your interface (supports comma-separated list)
    banDuration = 18000;  # 5 hours
    logLevel = "info";    # error, warn, info, or debug
  };

  # Kernel modules are automatically loaded by the module
}
```

### Step 3: Deploy

```bash
sudo nixos-rebuild switch --flake /etc/nixos#yourhostname
```

## Option 2: Direct Installation (No Flake)

### Install Package

```bash
# Install to profile
nix profile install github:spaiter/BitTorrentBlocker

# Verify
btblocker --version
```

### Manual Setup

```bash
# Create ipset
sudo ipset create torrent_block hash:ip timeout 18000

# Setup iptables
sudo iptables -t mangle -A PREROUTING -i eth0 -j NFQUEUE --queue-num 0
sudo iptables -A FORWARD -m set --match-set torrent_block src -j DROP

# Run blocker
sudo btblocker
```

## Verify It's Working

```bash
# Check service status (if using NixOS module)
systemctl status btblocker

# View logs
journalctl -u btblocker -f

# Check banned IPs
sudo ipset list torrent_block

# Check rules
sudo iptables -L -n -v
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `enable` | false | Enable the service |
| `interface` | "eth0" | Network interface(s) to monitor (comma-separated) |
| `ipsetName` | "torrent_block" | Name of ipset |
| `banDuration` | 18000 | Ban time in seconds |
| `logLevel` | "info" | Log level: error, warn, info, debug |
| `detectionLogPath` | "" | Path to detection log file (empty = disabled) |
| `monitorOnly` | false | If true, only log detections without banning |
| `firewallBackend` | "nftables" | Firewall backend (nftables or iptables) |
| `cleanupOnStop` | false | Destroy ipset when service stops |
| `whitelistPorts` | [22,53,80,443,...] | Ports to never block |

## Common Tasks

### Update Package

```bash
# Update flake
cd /etc/nixos
nix flake update

# Rebuild
sudo nixos-rebuild switch --flake .#yourhostname
```

### Enable Monitor-Only Mode

For testing without blocking:
```nix
services.btblocker.monitorOnly = true;
```

### Enable Detection Logging

For detailed analysis:
```nix
services.btblocker.detectionLogPath = "/var/log/btblocker/detections.log";
```

### Monitor Multiple Interfaces

```nix
services.btblocker.interface = "eth0,eth1,wlan0";  # Comma-separated
```

### Longer Ban Duration

```nix
services.btblocker.banDuration = 86400;  # 24 hours
```

### Enable Debug Logging

For troubleshooting:
```nix
services.btblocker.logLevel = "debug";
```

Then watch detailed logs:
```bash
journalctl -u btblocker -f
```

## Troubleshooting

### Service won't start

```bash
# Check logs
journalctl -u btblocker -xe

# Load kernel modules
sudo modprobe nfnetlink_queue

# Verify modules
lsmod | grep nfnetlink
```

### No traffic being analyzed

```bash
# Check iptables rules
sudo iptables -t mangle -L -n -v

# Verify queue exists
cat /proc/net/netfilter/nfnetlink_queue
```

### Too many false positives

Add ports to whitelist:
```nix
services.btblocker.whitelistPorts = [ 22 53 80 443 8080 ];
```

Or use monitor-only mode for testing:
```nix
services.btblocker.monitorOnly = true;
```

## Full Documentation

- [NIX_INSTALLATION.md](NIX_INSTALLATION.md) - Complete installation guide
- [NIXOS_DEPLOYMENT.md](NIXOS_DEPLOYMENT.md) - Detailed deployment guide
- [CACHIX_SETUP.md](CACHIX_SETUP.md) - Binary cache setup

## Example: Complete NixOS Configuration

```nix
{ config, pkgs, ... }:

{
  imports = [ ./hardware-configuration.nix ];

  # Boot
  boot = {
    kernelModules = [ "ip_set" "ip_set_hash_ip" ];
    loader.grub.enable = true;
  };

  # Networking
  networking = {
    hostName = "myserver";
    firewall.enable = true;
  };

  # BitTorrent Blocker
  services.btblocker = {
    enable = true;
    interface = "enp1s0";
    banDuration = 18000;
    logLevel = "info";
    ipsetName = "torrent_block";
    whitelistPorts = [ 22 53 80 443 853 ];
  };

  # Optional: Resource limits
  systemd.services.btblocker.serviceConfig = {
    CPUQuota = "50%";
    MemoryMax = "512M";
  };

  # System packages
  environment.systemPackages = with pkgs; [
    btblocker
    ipset
    iptables
    tcpdump
  ];

  system.stateVersion = "23.11";
}
```

## Support

- Issues: https://github.com/spaiter/BitTorrentBlocker/issues
- Docs: https://github.com/spaiter/BitTorrentBlocker/tree/main/docs
