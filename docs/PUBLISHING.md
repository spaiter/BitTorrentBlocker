# Automated Package Publishing

This project uses GitHub Actions to automatically build and publish packages across multiple platforms when a new release is created.

## 🚀 How It Works

### Automatic Release Creation

1. **Push commits to `main` branch** with conventional commit messages
2. **Release workflow automatically**:
   - Determines version bump (major/minor/patch)
   - Updates version in `cmd/btblocker/main.go` and `flake.nix`
   - Creates git tag (e.g., `v0.2.1`)
   - Creates GitHub release with changelog

3. **Build workflow triggers** on release creation and publishes:
   - Cross-platform binaries (Linux, Windows, macOS)
   - Docker images (multi-arch)
   - Nix packages (via Cachix)
   - Homebrew formula

## 📦 Published Packages

### 1. GitHub Releases - Binary Downloads

**Platforms:**
- Linux: `amd64`, `arm64`, `arm`
- Windows: `amd64`, `arm64`
- macOS: `amd64`, `arm64`

**Installation:**
```bash
# Download latest release for your platform
curl -LO https://github.com/spaiter/BitTorrentBlocker/releases/latest/download/btblocker-VERSION-linux-amd64.tar.gz

# Extract
tar -xzf btblocker-VERSION-linux-amd64.tar.gz

# Install
sudo mv btblocker-VERSION-linux-amd64 /usr/local/bin/btblocker
sudo chmod +x /usr/local/bin/btblocker
```

**Checksums:**
Each release includes SHA256 checksums:
```bash
curl -LO https://github.com/spaiter/BitTorrentBlocker/releases/latest/download/btblocker-VERSION-linux-amd64.tar.gz.sha256
sha256sum -c btblocker-VERSION-linux-amd64.tar.gz.sha256
```

### 2. Docker - GitHub Container Registry

**Images:**
- `ghcr.io/spaiter/btblocker:latest` - Latest stable release
- `ghcr.io/spaiter/btblocker:vX.Y.Z` - Specific version

**Architectures:**
- `linux/amd64`
- `linux/arm64`

**Usage:**
```bash
# Pull latest image
docker pull ghcr.io/spaiter/btblocker:latest

# Run with required capabilities
docker run --rm \
  --cap-add=NET_ADMIN \
  --network host \
  ghcr.io/spaiter/btblocker:latest

# Run with custom configuration
docker run --rm \
  --cap-add=NET_ADMIN \
  --network host \
  -v /path/to/config:/config \
  ghcr.io/spaiter/btblocker:latest
```

**Docker Compose Example (Compose V2):**
```yaml
# compose.yml
services:
  btblocker:
    image: ghcr.io/spaiter/btblocker:latest
    cap_add:
      - NET_ADMIN
    network_mode: host
    restart: unless-stopped
```

Run with: `docker compose up -d`

### 3. Nix - Cachix Binary Cache

**Installation:**
```bash
# Direct install
nix profile install github:spaiter/BitTorrentBlocker

# Try without installing
nix run github:spaiter/BitTorrentBlocker

# Specific version
nix profile install github:spaiter/BitTorrentBlocker/v0.2.1
```

**NixOS Configuration:**
```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    btblocker.url = "github:spaiter/BitTorrentBlocker";
  };

  outputs = { nixpkgs, btblocker, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        btblocker.nixosModules.default
        {
          services.btblocker = {
            enable = true;
            interface = "eth0";
          };
        }
      ];
    };
  };
}
```

**Binary Cache:**
Pre-built binaries are available from Cachix (https://btblocker.cachix.org):
```bash
# Configure Cachix
cachix use btblocker

# Or manually add to /etc/nixos/configuration.nix
nix.settings = {
  substituters = [ "https://btblocker.cachix.org" ];
  trusted-public-keys = [ "btblocker.cachix.org-1:..." ];
};
```

### 4. Homebrew (Future)

**Installation (when formula is published to tap):**
```bash
# Add tap
brew tap spaiter/btblocker

# Install
brew install btblocker
```

**Manual installation from formula:**
```bash
# Download formula from latest release
curl -LO https://github.com/spaiter/BitTorrentBlocker/releases/latest/download/btblocker.rb

# Install
brew install btblocker.rb
```

## 🔧 Manual Release Process

If you need to create a release manually:

### 1. Using GitHub CLI

```bash
# Create release with automatic version detection
gh release create v0.3.0 --title "Release v0.3.0" --generate-notes

# Or with custom notes
gh release create v0.3.0 --title "Release v0.3.0" --notes "Custom release notes"
```

### 2. Trigger Manual Build

You can manually trigger the build workflow:

```bash
# Via GitHub CLI
gh workflow run build-release.yml -f version=v0.3.0

# Or via GitHub UI
# Go to Actions → Build and Publish Release → Run workflow
```

## 🏗️ Build Matrix

The build workflow creates binaries for:

| OS | Architecture | CGO | Notes |
|----|--------------|-----|-------|
| Linux | amd64 | ✅ | Full support with nfqueue |
| Linux | arm64 | ✅ | Cross-compiled |
| Linux | arm | ✅ | Cross-compiled |
| Windows | amd64 | ❌ | Limited functionality (no nfqueue) |
| Windows | arm64 | ❌ | Limited functionality |
| macOS | amd64 | ❌ | Limited functionality |
| macOS | arm64 | ❌ | Limited functionality |

**Note:** Non-Linux builds are provided for development/testing but lack nfqueue support (Linux-only).

## 📋 Workflow Files

### `.github/workflows/release.yml`
- Triggers on push to `main`
- Analyzes commit messages
- Auto-bumps version
- Creates git tag and GitHub release

### `.github/workflows/build-release.yml`
- Triggers on release creation
- Builds cross-platform binaries
- Publishes Docker images
- Creates Homebrew formula

### `.github/workflows/nix.yml`
- Triggers on push and tags
- Builds Nix package
- Pushes to Cachix binary cache

## 🔐 Required Secrets

To enable automated publishing, configure these secrets in GitHub repository settings:

### CACHIX_AUTH_TOKEN
Binary cache for Nix packages.

**Setup:**
```bash
# Create Cachix account at https://cachix.org
# Create cache named "btblocker"
# Generate auth token
cachix authtoken

# Add to GitHub secrets
gh secret set CACHIX_AUTH_TOKEN
```

### GITHUB_TOKEN (Automatic)
Automatically provided by GitHub Actions for:
- Creating releases
- Uploading release assets
- Pushing Docker images to ghcr.io

## 🧪 Testing Releases

### Test Docker Build Locally

```bash
# Build image
docker build -t btblocker:test \
  --build-arg VERSION=0.3.0-test \
  --build-arg COMMIT=$(git rev-parse HEAD) \
  --build-arg DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  .

# Test run
docker run --rm btblocker:test --help
```

### Test Nix Build Locally

```bash
# Build package
nix build .#btblocker --print-build-logs

# Test binary
./result/bin/btblocker --help

# Check dependencies
nix path-info .#btblocker --closure-size
```

### Test Cross-Platform Builds

```bash
# Linux ARM64
GOOS=linux GOARCH=arm64 CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc make build

# Windows
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 make build

# macOS ARM64
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 make build
```

## 🐛 Troubleshooting

### Release Not Creating Binaries

1. Check release workflow completed: `gh run list --workflow=release.yml`
2. Check build workflow triggered: `gh run list --workflow=build-release.yml`
3. View logs: `gh run view <run-id> --log`

### Docker Image Not Appearing

1. Verify GITHUB_TOKEN permissions include `packages: write`
2. Check Docker build job: `gh run view <run-id> --log`
3. Verify image: `docker pull ghcr.io/spaiter/btblocker:latest`

### Nix Package Not in Cache

1. Check CACHIX_AUTH_TOKEN secret is set
2. Verify Nix workflow completed: `gh run list --workflow=nix.yml`
3. Test cache: `nix-store --option substituters https://btblocker.cachix.org --query`

### Cross-Compilation Failures

Linux ARM builds require cross-compilation toolchains:
```bash
# Install on Ubuntu
sudo apt-get install gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf

# Test local build
CC=aarch64-linux-gnu-gcc GOOS=linux GOARCH=arm64 CGO_ENABLED=1 go build ./cmd/btblocker
```

## 📊 Release Checklist

Before creating a release:

- [ ] All tests passing (`make test`)
- [ ] Code coverage meets threshold (76%+)
- [ ] Documentation updated (README.md, CHANGELOG)
- [ ] Version bumped in main.go and flake.nix (automatic)
- [ ] Conventional commit messages used
- [ ] CACHIX_AUTH_TOKEN secret configured
- [ ] Docker build tested locally
- [ ] Nix build tested locally

## 🔄 Version Bump Examples

| Commit Message | Version Change |
|----------------|----------------|
| `feat: add new detection method` | 0.2.0 → 0.3.0 (minor) |
| `fix: handle edge case in MSE detection` | 0.2.0 → 0.2.1 (patch) |
| `perf: optimize HTTP detection` | 0.2.0 → 0.2.1 (patch) |
| `feat!: change API interface` | 0.2.0 → 1.0.0 (major) |

## 📚 Additional Resources

- [Conventional Commits](https://www.conventionalcommits.org/)
- [Semantic Versioning](https://semver.org/)
- [GitHub Container Registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
- [Cachix Documentation](https://docs.cachix.org/)
- [Docker Multi-Platform Builds](https://docs.docker.com/build/building/multi-platform/)
