# GitHub Actions Workflows

This directory contains the CI/CD pipelines for BitTorrent Blocker.

## Active Workflows

### `pipeline.yml` - Main CI/CD Pipeline ⭐
The unified pipeline that handles everything from testing to release:

**Stages:**
1. **Test** (parallel):
   - Unit tests (Go 1.20 & 1.21)
   - Integration tests
   - E2E tests
   - Linting

2. **Build** (after tests pass):
   - Build binaries for 7 platforms (Linux, Windows, macOS)
   - Build Nix package
   - Upload artifacts

3. **Release** (after builds):
   - Determine version bump (major/minor/patch from conventional commits)
   - Create GitHub release with tag
   - Generate release notes

4. **Publish** (after release):
   - Upload binaries to GitHub Release
   - Push Docker images to GHCR
   - Push Nix packages to Cachix

**Triggers:**
- Push to `main` - Full pipeline (test → build → release → publish)
- Pull requests - Tests only

**Version Bumping:**
- `feat:` → minor version bump
- `fix:`, `perf:`, `refactor:` → patch version bump
- `feat!:`, `BREAKING CHANGE:` → major version bump

### `nix.yml` - Nix Maintenance
Updates flake.lock automatically when dependencies change.

**Triggers:** Push to `main`

### `update-flake.yml` - Vendor Hash Updates
Updates vendorHash in flake.nix when Go dependencies change.

**Triggers:** Changes to `go.mod` or `go.sum` on `main`

## Disabled Workflows

These workflows have been replaced by `pipeline.yml`:

- `ci.yml.disabled` - Replaced by pipeline test stage
- `release.yml.disabled` - Replaced by pipeline release stage
- `build-release.yml.disabled` - Replaced by pipeline build/publish stages

To re-enable, remove the `.disabled` extension.

## Pipeline Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│  Push to main                                                │
└────────────────────┬────────────────────────────────────────┘
                     │
         ┌───────────▼───────────┐
         │   STAGE 1: TEST       │
         │  ┌─────────────────┐  │
         │  │  Unit Tests     │  │
         │  │  Integration    │  │ (parallel)
         │  │  E2E Tests      │  │
         │  │  Lint           │  │
         │  └─────────────────┘  │
         └───────────┬───────────┘
                     │ (all pass)
         ┌───────────▼────────────┐
         │   STAGE 2: BUILD       │
         │  ┌─────────────────┐   │
         │  │  7 Platforms    │   │ (parallel)
         │  │  Nix Package    │   │
         │  └─────────────────┘   │
         └───────────┬────────────┘
                     │ (all succeed)
         ┌───────────▼────────────┐
         │  STAGE 3: RELEASE      │
         │  ┌─────────────────┐   │
         │  │ Version Bump    │   │
         │  │ Create Tag      │   │
         │  │ GitHub Release  │   │
         │  └─────────────────┘   │
         └───────────┬────────────┘
                     │
         ┌───────────▼────────────┐
         │  STAGE 4: PUBLISH      │
         │  ┌─────────────────┐   │
         │  │ Upload Binaries │   │ (parallel)
         │  │ Push Docker     │   │
         │  │ Push to Cachix  │   │
         │  └─────────────────┘   │
         └────────────────────────┘
```

## Artifacts

- **Binaries**: Available as GitHub Release assets
- **Docker**: `ghcr.io/spaiter/btblocker:latest` and `ghcr.io/spaiter/btblocker:v{version}`
- **Nix**: Available from Cachix `btblocker` cache

## Secrets Required

- `GITHUB_TOKEN` - Automatic, provided by GitHub
- `CODECOV_TOKEN` - For code coverage uploads
- `CACHIX_AUTH_TOKEN` - For pushing to Cachix

## Testing Locally

```bash
# Run tests (same as pipeline stage 1)
go test ./... -v -race

# Build (same as pipeline stage 2)
make build

# Simulate version bump
git log --pretty=%B | grep -E "^(feat|fix):"
```
