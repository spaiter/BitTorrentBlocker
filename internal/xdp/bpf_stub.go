//go:build !linux

package xdp

import (
	"fmt"
	"runtime"

	"github.com/cilium/ebpf"
)

// Stub implementation for non-Linux platforms
// The actual eBPF bytecode will be generated on Linux using: go generate ./internal/xdp

type bpfObjects struct {
	XdpBlocker *ebpf.Program
	BlockedIps *ebpf.Map
}

func (o *bpfObjects) Close() error {
	if o.XdpBlocker != nil {
		o.XdpBlocker.Close()
	}
	if o.BlockedIps != nil {
		o.BlockedIps.Close()
	}
	return nil
}

func loadBpfObjects(obj *bpfObjects, opts interface{}) error {
	return fmt.Errorf("XDP is only supported on Linux (current platform: %s)", runtime.GOOS)
}

// Placeholder - actual implementation will be in generated bpf_bpfel.go and bpf_bpfeb.go
var _ = bpfObjects{}
