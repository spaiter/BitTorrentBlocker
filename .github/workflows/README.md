# GitHub Actions Workflows

This directory contains the CI/CD pipelines for BitTorrent Blocker.

## Active Workflows

### `pipeline.yml` - Complete CI/CD Pipeline ⭐
**The only active workflow** - handles everything from testing to maintenance:

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

5. **Maintenance** (after publish):
   - Update flake.lock with latest dependencies

**Triggers:**
- Push to `main` - Full pipeline (test → build → release → publish → maintenance)
- Pull requests - Tests only

**Version Bumping:**
- `feat:` → minor version bump
- `fix:`, `perf:`, `refactor:` → patch version bump
- `feat!:`, `BREAKING CHANGE:` → major version bump

## Legacy Workflows

All legacy workflows have been removed and consolidated into the single `pipeline.yml` workflow:

- ~~`ci.yml`~~ - Removed (now: pipeline stage 1 - Tests)
- ~~`release.yml`~~ - Removed (now: pipeline stage 3 - Release)
- ~~`build-release.yml`~~ - Removed (now: pipeline stages 2 & 4 - Build & Publish)
- ~~`nix.yml`~~ - Removed (now: pipeline stage 5 - Maintenance)
- ~~`update-flake.yml`~~ - Removed (vendor hash updates no longer needed with committed vendor/)

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
         └───────────┬────────────┘
                     │
         ┌───────────▼────────────┐
         │ STAGE 5: MAINTENANCE   │
         │  ┌─────────────────┐   │
         │  │ Update flake.lock│  │
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
