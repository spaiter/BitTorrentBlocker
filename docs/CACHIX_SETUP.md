# Cachix Setup Guide

This guide explains how to set up Cachix for the BitTorrent Blocker project to provide binary caching.

## What is Cachix?

Cachix is a binary cache service for Nix that speeds up builds by caching compiled artifacts. Instead of building from source every time, users can download pre-built binaries.

## Setting Up Cachix (For Maintainers)

### 1. Create a Cachix Account

1. Go to https://cachix.org
2. Sign up with your GitHub account
3. Create a new cache named `btblocker`

### 2. Get Your Auth Token

```bash
# Install cachix
nix-env -iA cachix -f https://cachix.org/api/v1/install

# Login
cachix authtoken YOUR_AUTH_TOKEN
```

### 3. Add Cachix Secret to GitHub

1. Go to your repository settings: https://github.com/spaiter/BitTorrentBlocker/settings/secrets/actions
2. Click "New repository secret"
3. Name: `CACHIX_AUTH_TOKEN`
4. Value: Your Cachix auth token from https://cachix.org/api
5. Click "Add secret"

### 4. Get Your Public Key

After the first successful GitHub Actions run:

1. Go to https://btblocker.cachix.org
2. Click on "Configure binary cache"
3. Copy the public key

### 5. Update Documentation

Update [NIX_INSTALLATION.md](NIX_INSTALLATION.md) with the correct public key:

```nix
nix.settings = {
  substituters = [ "https://btblocker.cachix.org" ];
  trusted-public-keys = [ "btblocker.cachix.org-1:YOUR_ACTUAL_PUBLIC_KEY" ];
};
```

## Using Cachix (For Users)

### Method 1: Using cachix CLI (Easiest)

```bash
# Install cachix
nix-env -iA cachix -f https://cachix.org/api/v1/install

# Use the btblocker cache
cachix use btblocker
```

### Method 2: NixOS Configuration

Add to `/etc/nixos/configuration.nix`:

```nix
{
  nix.settings = {
    substituters = [
      "https://cache.nixos.org"
      "https://btblocker.cachix.org"
    ];
    trusted-public-keys = [
      "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
      "btblocker.cachix.org-1:5ER23eujq+x4QtEDoQEcXP5XD57F8RA/nXMtT0Hphk="
    ];
  };
}
```

Then rebuild:
```bash
sudo nixos-rebuild switch
```

### Method 3: Flake Configuration

Add to your `flake.nix`:

```nix
{
  nixConfig = {
    extra-substituters = [ "https://btblocker.cachix.org" ];
    extra-trusted-public-keys = [ "btblocker.cachix.org-1:5ER23eujq+x4QtEDoQEcXP5XD57F8RA/nXMtT0Hphk=" ];
  };
}
```

## Verifying Cachix is Working

```bash
# Clear local cache to test
nix store gc

# Build with verbose output
nix build github:spaiter/BitTorrentBlocker --print-build-logs

# You should see "copying path ... from 'https://btblocker.cachix.org'"
```

## GitHub Actions Workflow

The `.github/workflows/nix.yml` is already configured to:

1. Build the package on every push
2. Push successful builds to Cachix (only on main branch)
3. Skip pushing on pull requests (save bandwidth)

Key configuration in the workflow:

```yaml
- name: Setup Cachix
  uses: cachix/cachix-action@v14
  with:
    name: btblocker
    authToken: '${{ secrets.CACHIX_AUTH_TOKEN }}'
    skipPush: ${{ github.event_name == 'pull_request' }}
```

## Cache Management

### View Cache Contents

Visit: https://btblocker.cachix.org

### Clear Cache (if needed)

```bash
# Login to cachix
cachix authtoken YOUR_AUTH_TOKEN

# Remove specific path
cachix push btblocker --remove /nix/store/HASH-btblocker-VERSION
```

### Cache Statistics

- View build logs: https://github.com/spaiter/BitTorrentBlocker/actions
- View cache usage: https://btblocker.cachix.org (requires login)

## Troubleshooting

### "error: unable to download ... 403 Forbidden"

The cache might be private. Make sure:
1. Cache is set to public at https://btblocker.cachix.org/settings
2. Your CACHIX_AUTH_TOKEN is valid

### "untrusted substituter 'https://btblocker.cachix.org'"

You need to add the cache to trusted substituters:

```bash
# For current user
mkdir -p ~/.config/nix
echo "trusted-substituters = https://btblocker.cachix.org" >> ~/.config/nix/nix.conf

# For system-wide (NixOS)
# Add to configuration.nix as shown above
```

### Cache not being used

1. Verify cache is accessible: `curl https://btblocker.cachix.org/nix-cache-info`
2. Check your nix.conf: `nix show-config | grep substituters`
3. Try with explicit substituter: `nix build --substituters https://btblocker.cachix.org`

## Benefits of Binary Caching

- **Faster installations**: Download binaries instead of compiling from source
- **Reduced bandwidth**: GitHub Actions pushes once, users download many times
- **Consistent builds**: Everyone gets the same binary
- **Save time**: No need to build Go dependencies every time

## Alternative: Self-Hosted Binary Cache

If you prefer self-hosting, see:
- https://nixos.org/manual/nix/stable/package-management/binary-cache-substituter.html
- https://github.com/nix-community/nix-serve

## See Also

- [NIX_INSTALLATION.md](NIX_INSTALLATION.md) - Installation guide
- [NIXOS_DEPLOYMENT.md](NIXOS_DEPLOYMENT.md) - Deployment guide
- Cachix Documentation: https://docs.cachix.org/
