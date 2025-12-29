# Nix Installation Guide

This guide explains how to install and use BitTorrent Blocker on NixOS or any system with Nix package manager.

## Prerequisites

- NixOS or Nix package manager installed
- Nix flakes enabled (recommended)

## Enable Flakes (if not already enabled)

Add to your `/etc/nixos/configuration.nix` or `~/.config/nix/nix.conf`:

```nix
nix.settings.experimental-features = [ "nix-command" "flakes" ];
```

Or for non-NixOS systems:
```bash
mkdir -p ~/.config/nix
echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf
```

## Installation Methods

### Method 1: Direct Installation from GitHub (Recommended)

Install directly from this repository:

```bash
# Try it without installing
nix run github:spaiter/BitTorrentBlocker

# Install to your profile
nix profile install github:spaiter/BitTorrentBlocker

# Or using legacy nix-env
nix-env -iA packages.x86_64-linux.btblocker -f https://github.com/spaiter/BitTorrentBlocker/archive/main.tar.gz
```

### Method 2: Using Flake in NixOS Configuration

Add to your `/etc/nixos/flake.nix`:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    btblocker = {
      url = "github:spaiter/BitTorrentBlocker";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, btblocker, ... }: {
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

Then in your `/etc/nixos/configuration.nix`:

```nix
{
  # Enable the BitTorrent blocker service
  services.btblocker = {
    enable = true;
    queueNum = 0;
    entropyThreshold = 7.6;
    ipsetName = "torrent_block";
    banDuration = "18000";  # 5 hours
    interfaces = [ "eth0" ];  # Your network interface(s)
  };

  # Ensure required kernel modules are loaded
  boot.kernelModules = [ "nfnetlink_queue" "xt_NFQUEUE" ];
}
```

Rebuild your system:
```bash
sudo nixos-rebuild switch
```

### Method 3: Using Overlay

Add the overlay to your configuration:

```nix
{ config, pkgs, ... }:

{
  nixpkgs.overlays = [
    (import (builtins.fetchTarball {
      url = "https://github.com/spaiter/BitTorrentBlocker/archive/main.tar.gz";
    })).overlays.default
  ];

  environment.systemPackages = with pkgs; [
    btblocker
  ];
}
```

### Method 4: Local Development

Clone the repository and build locally:

```bash
# Clone repository
git clone https://github.com/spaiter/BitTorrentBlocker.git
cd BitTorrentBlocker

# Build the package
nix build

# Run directly
./result/bin/btblocker

# Enter development shell
nix develop
```

## Using Cachix (Optional but Recommended)

To speed up builds, use our Cachix binary cache:

```bash
# Install cachix if not already installed
nix-env -iA cachix -f https://cachix.org/api/v1/install

# Use the btblocker cache
cachix use btblocker
```

Or add to your Nix configuration:

```nix
nix.settings = {
  substituters = [ "https://btblocker.cachix.org" ];
  trusted-public-keys = [ "btblocker.cachix.org-1:5ER23eujq+x4QtEDoQEcXP5XD57F8RA/nXMtT0Hphk=" ];
};
```

## Verification

After installation, verify it works:

```bash
# Check version
btblocker --version

# View help (may require root)
sudo btblocker --help
```

## NixOS Service Configuration

Complete example for `/etc/nixos/configuration.nix`:

```nix
{ config, pkgs, ... }:

{
  imports = [
    # ... your other imports
  ];

  # Add the package to system packages
  environment.systemPackages = with pkgs; [
    btblocker
    ipset
    iptables
  ];

  # Enable the service
  services.btblocker = {
    enable = true;

    # Network configuration
    interfaces = [ "eth0" "wlan0" ];  # Monitor multiple interfaces

    # Detection parameters
    queueNum = 0;
    entropyThreshold = 7.6;
    minPayloadSize = 60;

    # Blocking configuration
    ipsetName = "torrent_block";
    banDuration = "18000";  # 5 hours in seconds

    # Whitelist common services
    whitelistPorts = [
      22    # SSH
      53    # DNS
      80    # HTTP
      443   # HTTPS
      853   # DNS over TLS
      5222  # XMPP client
      5269  # XMPP server
    ];
  };

  # Load required kernel modules
  boot.kernelModules = [
    "nfnetlink_queue"
    "xt_NFQUEUE"
  ];

  # Optional: Add resource limits
  systemd.services.btblocker.serviceConfig = {
    CPUQuota = "50%";
    MemoryMax = "512M";
  };
}
```

## Managing the Service

```bash
# Start the service
sudo systemctl start btblocker

# Stop the service
sudo systemctl stop btblocker

# Check status
sudo systemctl status btblocker

# View logs
sudo journalctl -u btblocker -f

# Check banned IPs
sudo ipset list torrent_block

# Check iptables rules
sudo iptables -L -n -v
sudo iptables -t mangle -L -n -v
```

## Pinning a Specific Version

To use a specific version/commit:

```nix
btblocker.url = "github:spaiter/BitTorrentBlocker/v1.0.0";  # Tag
# or
btblocker.url = "github:spaiter/BitTorrentBlocker/abc123";  # Commit hash
```

## Updating

### For flake-based installations:

```bash
# Update flake inputs
nix flake update

# Rebuild
sudo nixos-rebuild switch
```

### For profile installations:

```bash
# Update to latest
nix profile upgrade btblocker

# Or reinstall
nix profile remove btblocker
nix profile install github:spaiter/BitTorrentBlocker
```

## Uninstalling

### Remove from profile:
```bash
nix profile remove btblocker
```

### Remove service:
In your `/etc/nixos/configuration.nix`:
```nix
services.btblocker.enable = false;
```

Then rebuild:
```bash
sudo nixos-rebuild switch

# Clean up ipset if needed
sudo ipset destroy torrent_block
```

## Development

Enter the development shell:

```bash
nix develop

# Now you have access to Go and all build tools
make build
make test
go run ./cmd/btblocker
```

## Troubleshooting

### "experimental feature 'flakes' not enabled"

Enable flakes as shown in the Prerequisites section.

### "hash mismatch in fixed-output derivation"

The vendorHash in `flake.nix` may be outdated. Update it by:

1. Set `vendorHash = pkgs.lib.fakeHash;` in flake.nix
2. Run `nix build`
3. Copy the correct hash from the error message
4. Update `vendorHash` in flake.nix

### Service won't start

```bash
# Check logs
journalctl -u btblocker -n 50

# Verify kernel modules
lsmod | grep nfnetlink_queue

# Load modules manually if needed
sudo modprobe nfnetlink_queue
```

### Binary cache not working

```bash
# Test cachix connection
cachix use btblocker

# Or manually add to /etc/nixos/configuration.nix
nix.settings.substituters = [ "https://cache.nixos.org" "https://btblocker.cachix.org" ];
```

## Support

- GitHub Issues: https://github.com/spaiter/BitTorrentBlocker/issues
- Documentation: https://github.com/spaiter/BitTorrentBlocker/tree/main/docs
- NixOS Deployment: [NIXOS_DEPLOYMENT.md](NIXOS_DEPLOYMENT.md)

## See Also

- [NIXOS_DEPLOYMENT.md](NIXOS_DEPLOYMENT.md) - Complete deployment guide
- [Architecture Documentation](../README.md#architecture) - Project structure
- [E2E Tests](../test/e2e/README.md) - Testing infrastructure
