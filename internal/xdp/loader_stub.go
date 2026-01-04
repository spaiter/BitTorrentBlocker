//go:build !linux

package xdp

import (
	"fmt"
	"runtime"
)

// XDPFilter represents the XDP-based packet filter
type XDPFilter struct {
	ifaceName string
}

// NewXDPFilter returns an error on non-Linux platforms
func NewXDPFilter(ifaceName string) (*XDPFilter, error) {
	return nil, fmt.Errorf("XDP is only supported on Linux (current platform: %s/%s)", runtime.GOOS, runtime.GOARCH)
}

// GetMapManager returns nil on stub implementation
func (f *XDPFilter) GetMapManager() *IPMapManager {
	return nil
}

// Close is a no-op on stub implementation
func (f *XDPFilter) Close() error {
	return nil
}

// GetInterfaceName returns empty string on stub
func (f *XDPFilter) GetInterfaceName() string {
	return ""
}

// GetStats returns error on stub
func (f *XDPFilter) GetStats() (map[string]interface{}, error) {
	return nil, fmt.Errorf("XDP not supported on %s", runtime.GOOS)
}
