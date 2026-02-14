# BitTorrent Blocker Documentation

Complete documentation index for the BitTorrent Blocker project.

## Quick Start

- **[README.md](README.md)** - Main documentation, installation, and usage guide
- **[CLAUDE.md](CLAUDE.md)** - Project architecture for AI development assistants

## Installation & Deployment

- **[README.md](README.md#installation)** - Installation methods
  - Binary releases (Linux, Windows, macOS)
  - Docker / Docker Compose deployment
  - Build from source

## Configuration & Usage

- **[README.md](README.md#configuration)** - Configuration reference
  - Environment variables
  - Config struct options
  - Log levels and detection logging
  - Monitor-only mode

- **[README.md](README.md#production-deployment)** - Production deployment scenarios
  - VPN/VPS providers
  - Educational institutions
  - Corporate networks
  - Home servers

## Performance & Optimization

- **[docs/performance/PERFORMANCE.md](docs/performance/PERFORMANCE.md)** - Benchmark results and analysis
  - Detector function performance (0.19 ns/op to 928 ns/op)
  - End-to-end throughput (135M - 920M packets/sec)
  - Zero-allocation design
  - Real-world throughput estimates by traffic type

- **[docs/performance/MULTITHREADING_ANALYSIS.md](docs/performance/MULTITHREADING_ANALYSIS.md)** - Concurrency architecture
  - Goroutine-based design (current default, optimal for <10 Gbps)
  - Processor-specific performance (AMD Ryzen, Intel, ARM)
  - NUMA tuning for multi-socket servers
  - Worker pool recommendations for high traffic

- **[docs/performance/GO_CONCURRENCY_PATTERNS.md](docs/performance/GO_CONCURRENCY_PATTERNS.md)** - Go optimization patterns
  - Why goroutines beat OS threads (1000× cheaper, 50× faster switching)
  - sync.Pool for buffer reuse (90% fewer allocations)
  - Atomic counters for lock-free statistics
  - Profile-Guided Optimization (PGO) for 3-5% free gains

- **[docs/performance/WORKER_POOL_EXAMPLE.md](docs/performance/WORKER_POOL_EXAMPLE.md)** - High-traffic optimization
  - Optional bounded concurrency for >10 Gbps scenarios
  - Integration guide with code examples
  - Performance benchmarks and trade-offs

## Publishing & Release

- **[docs/PUBLISHING.md](docs/PUBLISHING.md)** - Automated package publishing
  - Automatic release creation from commits
  - Multi-platform binary builds (GitHub Actions)
  - Docker image publishing (GHCR)
  - Version bumping strategy (conventional commits)

## Development

- **[CLAUDE.md](CLAUDE.md)** - Development guide
  - Project architecture and component overview
  - Detection strategy and layer descriptions
  - Development commands (build, test, run)
  - Configuration and dependencies

- **[README.md](README.md#detection-accuracy)** - Detection methodology
  - 99.52% accuracy (validated against 416 protocols)
  - 11-layer detection strategy
  - Multi-BEP support (BEPs 5, 6, 10, 11, 14, 19, 29)
  - Context-specific thresholds (e.g., 6.5 for DH keys)

## Documentation by Use Case

### I want to install and use the blocker

1. **[README.md](README.md)** - Overview and installation options
2. **Docker**: See README Docker Compose section
3. **Binary**: See README releases section

### I want to understand performance

1. **[docs/performance/PERFORMANCE.md](docs/performance/PERFORMANCE.md)** - Benchmark results
2. **[docs/performance/MULTITHREADING_ANALYSIS.md](docs/performance/MULTITHREADING_ANALYSIS.md)** - Concurrency strategy
3. **[docs/performance/GO_CONCURRENCY_PATTERNS.md](docs/performance/GO_CONCURRENCY_PATTERNS.md)** - Optimization patterns
4. **[docs/performance/WORKER_POOL_EXAMPLE.md](docs/performance/WORKER_POOL_EXAMPLE.md)** - High-traffic optimization

### I want to deploy in production

1. **[README.md](README.md#production-deployment)** - Deployment scenarios
2. **High traffic (>10 Gbps)**: [docs/performance/WORKER_POOL_EXAMPLE.md](docs/performance/WORKER_POOL_EXAMPLE.md)
3. **Performance tuning**: [docs/performance/MULTITHREADING_ANALYSIS.md](docs/performance/MULTITHREADING_ANALYSIS.md)

### I want to build and release

1. **[docs/PUBLISHING.md](docs/PUBLISHING.md)** - Automated publishing workflow

### I want to contribute or develop

1. **[CLAUDE.md](CLAUDE.md)** - Architecture and development guide
2. **[README.md](README.md#detection-accuracy)** - Detection methodology
3. **[docs/performance/PERFORMANCE.md](docs/performance/PERFORMANCE.md)** - Performance characteristics

## File Organization

```
BitTorrentBlocker/
├── README.md                     # Main documentation (start here)
├── CLAUDE.md                     # AI development guide
├── DOCUMENTATION.md              # This file (documentation index)
│
└── docs/                         # All documentation
    ├── PUBLISHING.md             # Package publishing automation
    │
    └── performance/              # Performance & optimization guides
        ├── PERFORMANCE.md        # Benchmark results
        ├── MULTITHREADING_ANALYSIS.md # Threading strategy
        ├── GO_CONCURRENCY_PATTERNS.md # Go optimization patterns
        └── WORKER_POOL_EXAMPLE.md     # High-traffic optimization
```

## Documentation Status

| Document | Status | Purpose |
|----------|--------|---------|
| README.md | ✅ Current | Main entry point, installation, usage |
| CLAUDE.md | ✅ Current | AI development guide |
| docs/PUBLISHING.md | ✅ Current | Automated publishing |
| docs/performance/PERFORMANCE.md | ✅ Current | Benchmark results and analysis |
| docs/performance/MULTITHREADING_ANALYSIS.md | ✅ Current | Concurrency architecture |
| docs/performance/GO_CONCURRENCY_PATTERNS.md | ✅ Current | Go optimization patterns |
| docs/performance/WORKER_POOL_EXAMPLE.md | ✅ Current | High-traffic optimization |

## Support

- **Issues**: https://github.com/spaiter/BitTorrentBlocker/issues
- **Discussions**: https://github.com/spaiter/BitTorrentBlocker/discussions

---

**Last Updated**: 2026-01
**Documentation Version**: 2.0 (Streamlined)
