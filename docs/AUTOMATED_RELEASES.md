# Automated Release Workflow

This project uses GitHub Actions to automatically bump versions and create releases based on commit messages.

## How It Works

When you push commits to the `main` branch, the workflow:

1. **Analyzes commit messages** to determine the version bump type
2. **Automatically bumps the version** in `cmd/btblocker/main.go` and `flake.nix`
3. **Generates a changelog** from commit messages since the last tag
4. **Creates a git tag** with the new version
5. **Publishes a GitHub release** with the generated changelog

## Commit Message Convention

The workflow uses **conventional commits** to determine version bumps:

### Major Version (Breaking Changes)

Triggers a major version bump (e.g., v1.0.0 → v2.0.0):

```
feat!: redesign API interface

BREAKING CHANGE: The config structure has changed
```

Or:

```
refactor!: remove deprecated methods
```

### Minor Version (New Features)

Triggers a minor version bump (e.g., v0.2.0 → v0.3.0):

```
feat: add support for IPv6 detection

feat(dht): implement DHT v2 protocol detection
```

### Patch Version (Bug Fixes, Performance, Refactoring)

Triggers a patch version bump (e.g., v0.2.0 → v0.2.1):

```
fix: correct entropy calculation for edge case

perf: optimize signature matching loop

refactor: simplify UDP tracker detection
```

## Commit Message Format

Follow this format for automatic categorization in changelogs:

```
<type>[optional scope]: <description>

[optional body]

[optional footer]
```

### Types

- `feat:` or `feature:` - New features (minor bump)
- `fix:` - Bug fixes (patch bump)
- `perf:` or `optimize:` - Performance improvements (patch bump)
- `refactor:` - Code refactoring (patch bump)
- `docs:` - Documentation changes (no version bump, categorized)
- `chore:` - Maintenance tasks (no version bump, categorized)
- `build:` or `ci:` - Build/CI changes (no version bump, categorized)

### Breaking Changes

Add `!` after the type or add `BREAKING CHANGE:` in the footer to trigger a major version bump:

```
feat!: change API response format

BREAKING CHANGE: Response structure changed from array to object
```

## Examples

### Adding a Feature

```bash
git add internal/blocker/detectors.go
git commit -m "feat: add BitTorrent v2 detection support" \
  -m "Implements detection for the new BitTorrent v2 protocol (BEP 52)" \
  -m "Includes support for merkle trees and piece layers"
git push
```

This will trigger a **minor version bump** (e.g., v0.2.0 → v0.3.0).

### Fixing a Bug

```bash
git add internal/blocker/analyzer.go
git commit -m "fix: handle empty payload in MSE detection" \
  -m "Previously crashed on zero-length payloads"
git push
```

This will trigger a **patch version bump** (e.g., v0.2.0 → v0.2.1).

### Performance Optimization

```bash
git add internal/blocker/detectors.go
git commit -m "perf: optimize signature matching with Boyer-Moore" \
  -m "Reduces signature check time by 40% on average"
git push
```

This will trigger a **patch version bump** (e.g., v0.2.0 → v0.2.1).

### Breaking Change

```bash
git add internal/blocker/config.go
git commit -m "feat!: restructure configuration format" \
  -m "BREAKING CHANGE: Configuration now uses YAML instead of JSON" \
  -m "Users must migrate their config files to the new format"
git push
```

This will trigger a **major version bump** (e.g., v0.2.0 → v1.0.0).

### Multiple Commits

If you push multiple commits together, the workflow will:
- Use the **highest priority** bump type (major > minor > patch)
- Include **all commits** in the changelog, categorized by type

Example:

```bash
git commit -m "feat: add new detection method"
git commit -m "fix: correct edge case in existing detector"
git commit -m "docs: update README with new examples"
git push
```

This will trigger a **minor version bump** (feat takes priority over fix).

## Skipping Auto-Release

To skip automatic releases for specific commits, the workflow ignores:

1. **Documentation-only changes** (paths: `**.md`, `docs/**`)
2. **Configuration files** (`.github/**`, `.gitignore`, `LICENSE`)
3. **Version bump commits** (commits with "bump version to" in message)

To manually skip a release, use `[skip ci]` in your commit message:

```bash
git commit -m "chore: minor cleanup [skip ci]"
```

## Changelog Generation

The workflow automatically generates changelogs with sections:

- ✨ **Features** - New functionality
- 🐛 **Bug Fixes** - Bug fixes
- ⚡ **Performance** - Performance improvements
- ♻️ **Refactoring** - Code refactoring
- 📝 **Documentation** - Documentation changes
- 🔧 **Chores** - Maintenance tasks
- **Other Changes** - Uncategorized commits

Example changelog output:

```markdown
## What's Changed in v0.3.0

### ✨ Features
- feat: add BitTorrent v2 detection support (abc1234)
- feat(http): implement WebTorrent detection (def5678)

### 🐛 Bug Fixes
- fix: handle empty payload in MSE detection (ghi9012)

### ⚡ Performance
- perf: optimize signature matching with Boyer-Moore (jkl3456)

## Installation

### NixOS / Nix
\`\`\`bash
nix profile install github:spaiter/BitTorrentBlocker
\`\`\`

### From Source
\`\`\`bash
git clone https://github.com/spaiter/BitTorrentBlocker
cd BitTorrentBlocker
make build
\`\`\`

**Full Changelog**: https://github.com/spaiter/BitTorrentBlocker/compare/v0.2.0...v0.3.0
```

## Manual Release

If you need to create a release manually:

```bash
# Update version in files
sed -i 's/Version = ".*"/Version = "0.3.0"/' cmd/btblocker/main.go
sed -i 's/version = ".*";/version = "0.3.0";/' flake.nix

# Commit and push
git add cmd/btblocker/main.go flake.nix
git commit -m "chore: bump version to v0.3.0"
git push

# Create tag
git tag -a v0.3.0 -m "Release v0.3.0"
git push origin v0.3.0

# Create GitHub release
gh release create v0.3.0 --title "Release v0.3.0" --notes "Release notes here"
```

## Checking Release Status

View the workflow status:

```bash
# Check latest workflow runs
gh run list --workflow=release.yml

# View specific run details
gh run view <run-id>

# View workflow logs
gh run view <run-id> --log
```

## Troubleshooting

### Workflow Not Triggering

1. Check if your commit paths match the `paths-ignore` filter
2. Ensure you're pushing to the `main` branch
3. Verify GitHub Actions is enabled for the repository

### Version Bump Not Detected

1. Check your commit message format
2. Ensure you're using the correct type prefix (`feat:`, `fix:`, etc.)
3. Check workflow logs: `gh run view --log`

### Release Creation Failed

1. Check if you have the `GITHUB_TOKEN` permissions set correctly
2. Verify the tag doesn't already exist
3. Check workflow logs for specific errors

## Best Practices

1. **Write clear commit messages** - They become your changelog
2. **One logical change per commit** - Makes changelog more readable
3. **Use conventional commit format** - Enables automatic versioning
4. **Review generated releases** - Check the release notes after workflow completes
5. **Update docs when needed** - Add documentation for new features

## Workflow Configuration

The workflow is configured in `.github/workflows/release.yml`.

Key settings:
- Runs on: `push` to `main` branch
- Ignores: Documentation and config files
- Permissions: `contents: write` (for creating releases)
- Generates: Version bump commit, git tag, GitHub release

## See Also

- [Conventional Commits](https://www.conventionalcommits.org/)
- [Semantic Versioning](https://semver.org/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
