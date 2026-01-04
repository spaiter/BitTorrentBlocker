# XDP Build Notes

## eBPF Generation Requirement

The XDP package requires generating Go bindings from eBPF C code. This process **must be done on Linux** with the following prerequisites:

### Prerequisites

1. **Linux Kernel** 4.18+ (for XDP support)
2. **clang/LLVM** for compiling eBPF bytecode
3. **Go 1.20+**
4. **bpf2go tool** from cilium/ebpf

### Installation

```bash
# Install clang (Ubuntu/Debian)
sudo apt-get install clang llvm

# Install clang (Fedora/RHEL)
sudo dnf install clang llvm

# Install bpf2go tool
go install github.com/cilium/ebpf/cmd/bpf2go@latest
```

### Generating eBPF Bindings

On a Linux system with the prerequisites installed:

```bash
# From project root
make generate-ebpf

# Or manually
cd internal/xdp
go generate .
```

This will create:
- `bpf_bpfel.go` - Little-endian Go bindings
- `bpf_bpfeb.go` - Big-endian Go bindings
- `bpf_bpfel.o` - Little-endian eBPF object file
- `bpf_bpfeb.o` - Big-endian eBPF object file

### Development Workflow

#### On Windows (Development Machine)
1. Write XDP Go code (loader.go, map.go, etc.)
2. Write eBPF C code (blocker.c)
3. Commit changes to Git

#### On Linux (Build Machine or CI/CD)
1. Pull latest changes
2. Run `make generate-ebpf` to generate bindings
3. Commit generated files (bpf_bpfel.go, bpf_bpfeb.go)
4. Build with `make build`

### Why Linux Only?

The bpf2go tool requires:
1. Linux headers for eBPF type definitions
2. clang with eBPF target support
3. libbpf for eBPF program verification

These dependencies are Linux-specific and cannot be satisfied on Windows or macOS.

### Alternative: Pre-generated Bindings

For development without Linux access:
1. Generate bindings once on Linux or CI/CD
2. Commit the generated `bpf_bpfel.go` and `bpf_bpfeb.go` files
3. Regular Go builds will work on any platform (the eBPF bytecode is embedded in the Go code)

**Note**: Runtime XDP functionality still requires Linux 4.18+ with XDP kernel support. The bindings just allow the code to compile on other platforms.

### CI/CD Integration

Add to GitHub Actions workflow:

```yaml
- name: Install eBPF build dependencies
  run: |
    sudo apt-get update
    sudo apt-get install -y clang llvm libbpf-dev

- name: Generate eBPF bindings
  run: make generate-ebpf

- name: Build
  run: make build
```

### Troubleshooting

**Error: `bpf2go: command not found`**
```bash
go install github.com/cilium/ebpf/cmd/bpf2go@latest
export PATH=$PATH:$(go env GOPATH)/bin
```

**Error: `clang: command not found`**
```bash
# Install clang
sudo apt-get install clang llvm
```

**Error: `fatal error: 'linux/bpf.h' file not found`**
```bash
# Install kernel headers
sudo apt-get install linux-headers-$(uname -r)
```

**Error: `build constraints exclude all Go files`**
- This error occurs when trying to install bpf2go on Windows
- Solution: Generate bindings on Linux and commit them to Git
