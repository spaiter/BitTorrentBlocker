.PHONY: build run test generate-ebpf clean

# Generate eBPF bytecode from C source (requires Linux with clang)
generate-ebpf:
	@echo "Generating eBPF bytecode (requires Linux with clang)..."
	go generate ./internal/xdp

build:
	go build -o bin/btblocker ./cmd/btblocker

# Build with XDP support (requires eBPF bytecode to be generated first)
build-xdp: generate-ebpf build

run: build
	./bin/btblocker

test:
	go test ./...

clean:
	rm -rf bin/
	rm -f internal/xdp/bpf_bpfel.go internal/xdp/bpf_bpfeb.go internal/xdp/bpf_bpfel.o internal/xdp/bpf_bpfeb.o
