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
    interfaces = [ "eth0" ];  # Your interface
    queueNum = 0;
    entropyThreshold = 7.6;
    banDuration = "18000";  # 5 hours
  };

  # Load kernel modules
  boot.kernelModules = [ "nfnetlink_queue" "xt_NFQUEUE" ];
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
| `queueNum` | 0 | NFQUEUE number |
| `entropyThreshold` | 7.6 | Encryption detection threshold |
| `minPayloadSize` | 60 | Min bytes for analysis |
| `ipsetName` | "torrent_block" | Name of ipset |
| `banDuration` | "18000" | Ban time in seconds |
| `interfaces` | ["eth0"] | Interfaces to monitor |
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

### Adjust Sensitivity

More aggressive (blocks more):
```nix
services.btblocker.entropyThreshold = 7.0;  # Lower = more sensitive
```

Less aggressive (fewer false positives):
```nix
services.btblocker.entropyThreshold = 7.8;  # Higher = less sensitive
```

### Monitor Multiple Interfaces

```nix
services.btblocker.interfaces = [ "eth0" "eth1" "wlan0" ];
```

### Longer Ban Duration

```nix
services.btblocker.banDuration = "86400";  # 24 hours
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

Increase entropy threshold:
```nix
services.btblocker.entropyThreshold = 7.8;
```

Add ports to whitelist:
```nix
services.btblocker.whitelistPorts = [ 22 53 80 443 8080 ];
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
    kernelModules = [ "nfnetlink_queue" "xt_NFQUEUE" ];
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
    interfaces = [ "enp1s0" ];
    queueNum = 0;
    entropyThreshold = 7.6;
    banDuration = "18000";
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
