# Submitting BitTorrent Blocker to nixpkgs

This guide explains how to add BitTorrent Blocker to the official nixpkgs repository so it appears on search.nixos.org.

## Current Status

✅ **Published as Flake**: Available at `github:spaiter/BitTorrentBlocker`
❌ **Not in nixpkgs**: Not yet in the official nixpkgs repository

## Why Submit to nixpkgs?

Benefits of being in nixpkgs:
- 📦 **Discoverability**: Appears on search.nixos.org
- 🔍 **Searchable**: Users can find it with `nix search nixpkgs btblocker`
- 📊 **Official**: Part of the official Nix ecosystem
- 🎯 **Stable**: Included in NixOS releases
- 👥 **Community**: More contributors and users

## Prerequisites

Before submitting to nixpkgs:

1. **Create a stable release** with a git tag:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

2. **Test your package thoroughly**:
   - Unit tests pass
   - Integration tests pass
   - E2E tests pass
   - Package builds successfully

3. **Create a nixpkgs account** (if you don't have one):
   - Create an account on GitHub
   - Request to be added to nixpkgs maintainers (optional)

## Step-by-Step Submission Process

### 1. Fork and Clone nixpkgs

```bash
# Fork nixpkgs on GitHub first
git clone https://github.com/YOUR_USERNAME/nixpkgs
cd nixpkgs
git checkout master
git checkout -b add-btblocker
```

### 2. Create Package Directory

```bash
mkdir -p pkgs/by-name/bt/btblocker
```

### 3. Create package.nix

Copy the template from `docs/nixpkgs-package.nix` to `pkgs/by-name/bt/btblocker/package.nix`:

```nix
{ lib
, buildGoModule
, fetchFromGitHub
, pkg-config
, libnetfilter_queue
, libnfnetlink
}:

buildGoModule rec {
  pname = "btblocker";
  version = "0.1.0";

  src = fetchFromGitHub {
    owner = "spaiter";
    repo = "BitTorrentBlocker";
    rev = "v${version}";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; # Calculate this
  };

  vendorHash = "sha256-kQfQXHJHGIPiKr5AFgmYr3M2m1NRdOUby5vm1qdu13s=";

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    libnetfilter_queue
    libnfnetlink
  ];

  subPackages = [ "cmd/btblocker" ];

  ldflags = [
    "-s"
    "-w"
    "-X main.Version=${version}"
  ];

  meta = with lib; {
    description = "High-performance DPI-based BitTorrent traffic blocker for Linux";
    homepage = "https://github.com/spaiter/BitTorrentBlocker";
    changelog = "https://github.com/spaiter/BitTorrentBlocker/releases/tag/v${version}";
    license = licenses.mit;
    maintainers = with maintainers; [ ]; # Add your handle here
    platforms = platforms.linux;
    mainProgram = "btblocker";
  };
}
```

### 4. Calculate Source Hash

```bash
# In nixpkgs directory
nix-prefetch-url --unpack https://github.com/spaiter/BitTorrentBlocker/archive/refs/tags/v0.1.0.tar.gz

# Or use nix-prefetch-github
nix run nixpkgs#nix-prefetch-github -- spaiter BitTorrentBlocker --rev v0.1.0
```

Update the `hash` field in package.nix with the output.

### 5. Build and Test

```bash
# Build your package
nix-build -A btblocker

# Run the binary
./result/bin/btblocker --help

# Check metadata
nix eval --raw '.#btblocker.meta.description'
```

### 6. Run nixpkgs-review

```bash
# Install nixpkgs-review if needed
nix-env -iA nixpkgs.nixpkgs-review

# Review your changes
nixpkgs-review rev HEAD
```

### 7. Format and Check

```bash
# Format Nix code
nix fmt

# Check for common issues
nix flake check
```

### 8. Commit Your Changes

```bash
git add pkgs/by-name/bt/btblocker/package.nix
git commit -m "btblocker: init at 0.1.0"
```

**Commit message format**:
```
btblocker: init at 0.1.0

BitTorrent Blocker is a high-performance Go library and CLI tool for
detecting and blocking BitTorrent traffic using Deep Packet Inspection.
It combines detection techniques from nDPI, libtorrent, Suricata, and
Sing-box.

Features:
- Multi-protocol detection (TCP/UDP)
- MSE/PE encryption detection
- UDP tracker, DHT, uTP, PEX support
- Automatic IP banning with ipset
- SOCKS5 proxy unwrapping
```

### 9. Push and Create PR

```bash
git push origin add-btblocker
```

Then create a Pull Request on GitHub to NixOS/nixpkgs with:

**Title**: `btblocker: init at 0.1.0`

**Description**:
```markdown
## Description

This PR adds BitTorrent Blocker, a high-performance DPI-based BitTorrent traffic detection and blocking tool.

## Checklist

- [x] Built on NixOS
- [x] Tested on NixOS
- [x] Package builds successfully
- [x] Tests pass
- [x] Meta information is correct
- [x] Follows nixpkgs conventions

## Testing

```bash
nix-build -A btblocker
./result/bin/btblocker --help
```

## Additional Context

- Project: https://github.com/spaiter/BitTorrentBlocker
- License: MIT
- Platforms: Linux only (requires netfilter)
```

### 10. Respond to Review

nixpkgs maintainers will review your PR and may request changes:
- Code style improvements
- Better descriptions
- Additional tests
- License verification

Address their feedback and push updates.

## Alternative: Wait for Maturity

You might want to wait before submitting to nixpkgs if:
- The project is still in early development (< v1.0)
- APIs are still changing frequently
- You want more real-world testing first
- Documentation is incomplete

**Current recommendation**: Since your project is at v0.1.0, consider:
1. Use the flake for now (`github:spaiter/BitTorrentBlocker`)
2. Gather user feedback
3. Reach v1.0 with stable APIs
4. Then submit to nixpkgs

## Maintaining the Package

Once accepted into nixpkgs:
1. You'll need to submit PRs for updates
2. Watch for breakages in nixpkgs CI
3. Respond to issues filed against your package
4. Keep the package up to date

## Resources

- [nixpkgs Contributing Guide](https://github.com/NixOS/nixpkgs/blob/master/CONTRIBUTING.md)
- [nixpkgs Manual](https://nixos.org/manual/nixpkgs/stable/)
- [Go Packages in nixpkgs](https://nixos.org/manual/nixpkgs/stable/#sec-language-go)
- [Package by-name Structure](https://github.com/NixOS/nixpkgs/tree/master/pkgs/by-name)

## Questions?

- nixpkgs issues: https://github.com/NixOS/nixpkgs/issues
- Nix Discourse: https://discourse.nixos.org/
- Matrix: #nixos:nixos.org

## For Now: Use the Flake

Until the package is in nixpkgs, users can install via:

```bash
# Flake (recommended)
nix profile install github:spaiter/BitTorrentBlocker

# NixOS configuration
inputs.btblocker.url = "github:spaiter/BitTorrentBlocker";
```

This gives you all the benefits without waiting for nixpkgs inclusion!
