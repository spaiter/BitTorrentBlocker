.PHONY: build run test generate-ebpf generate-ebpf-docker test-xdp-docker clean

# Generate eBPF bytecode from C source (requires Linux with clang)
generate-ebpf:
	@echo "Generating eBPF bytecode (requires Linux with clang)..."
	go generate ./internal/xdp

# Generate eBPF bytecode using Docker (works on any platform)
generate-ebpf-docker:
	@echo "Generating eBPF bytecode using Docker..."
	docker build -f Dockerfile.ebpf-gen -t btblocker-ebpf-gen .
	docker run --rm -v "$(PWD):/src" btblocker-ebpf-gen

build:
	go build -o bin/btblocker ./cmd/btblocker

# Build with XDP support (requires eBPF bytecode to be generated first)
build-xdp: generate-ebpf build

run: build
	./bin/btblocker

test:
	go test ./...

# Run XDP integration tests using Docker (requires privileged container)
test-xdp-docker:
	@echo "Building XDP test container..."
	@# Temporarily disable .dockerignore to include test files
	@if [ -f .dockerignore ]; then mv .dockerignore .dockerignore.tmp; fi
	@docker build -f Dockerfile.xdp-test -t btblocker-xdp-test . || (mv .dockerignore.tmp .dockerignore 2>/dev/null; exit 1)
	@if [ -f .dockerignore.tmp ]; then mv .dockerignore.tmp .dockerignore; fi
	@echo "Running XDP integration tests (requires privileged mode)..."
	docker run --rm --privileged --network host btblocker-xdp-test

clean:
	rm -rf bin/
	rm -f internal/xdp/bpf_bpfel.go internal/xdp/bpf_bpfeb.go internal/xdp/bpf_bpfel.o internal/xdp/bpf_bpfeb.o
