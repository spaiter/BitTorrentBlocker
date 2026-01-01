# Git Hooks

This directory contains Git hooks that help maintain code quality.

## Pre-commit Hook

The pre-commit hook runs automatically before each commit and performs:

1. **Code formatting check** - Ensures code is properly formatted with `gofmt`
2. **Linting** - Runs `golangci-lint` to catch common issues
3. **Tests** - Runs all tests with race detector
4. **Debug statement check** - Warns about `fmt.Println` or `spew.Dump` in code
5. **TODO/FIXME check** - Suggests linking TODOs to issue numbers

## Setup

To enable the hooks, run:

```bash
git config core.hooksPath .githooks
```

This only needs to be done once after cloning the repository.

## Bypassing Hooks

If you need to commit without running the hooks (not recommended):

```bash
git commit --no-verify
```

## Requirements

The pre-commit hook requires:
- `gofmt` (included with Go)
- `golangci-lint` ([installation](https://golangci-lint.run/usage/install/))
- `go test` (included with Go)

## Testing the Hook

To test the hook manually:

```bash
./.githooks/pre-commit
```
