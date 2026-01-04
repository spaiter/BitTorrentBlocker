//go:build linux

package xdp

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf/link"
)

// Filter represents the XDP-based packet filter
type Filter struct {
	ifaceName string
	objs      *bpfObjects
	link      link.Link
	mapMgr    *IPMapManager
}

// NewXDPFilter creates and loads a new XDP filter on the specified interface
func NewXDPFilter(ifaceName string) (*Filter, error) {
	// Load pre-compiled eBPF objects
	objs := &bpfObjects{}
	if err := loadBpfObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("loading eBPF objects: %w", err)
	}

	// Get the network interface
	iface, err := getInterface(ifaceName)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("getting interface %s: %w", ifaceName, err)
	}

	// Attach XDP program to the interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpBlocker,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // Use generic mode for compatibility
	})
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("attaching XDP program to %s: %w", ifaceName, err)
	}

	log.Printf("XDP filter loaded on interface %s (index %d)", ifaceName, iface.Index)

	// Create IP map manager
	mapMgr := NewIPMapManager(objs.BlockedIps)

	return &Filter{
		ifaceName: ifaceName,
		objs:      objs,
		link:      l,
		mapMgr:    mapMgr,
	}, nil
}

// GetMapManager returns the IP map manager for adding/removing blocked IPs
func (f *Filter) GetMapManager() *IPMapManager {
	return f.mapMgr
}

// Close detaches the XDP program and releases all resources
func (f *Filter) Close() error {
	log.Printf("Detaching XDP filter from interface %s", f.ifaceName)

	// Stop periodic cleanup
	if f.mapMgr != nil {
		_ = f.mapMgr.Close()
	}

	// Detach XDP program
	if f.link != nil {
		if err := f.link.Close(); err != nil {
			log.Printf("Warning: failed to detach XDP link: %v", err)
		}
	}

	// Close eBPF objects (maps and programs)
	if f.objs != nil {
		if err := f.objs.Close(); err != nil {
			log.Printf("Warning: failed to close eBPF objects: %v", err)
		}
	}

	return nil
}

// GetInterfaceName returns the name of the interface this filter is attached to
func (f *Filter) GetInterfaceName() string {
	return f.ifaceName
}

// GetStats returns statistics about the XDP filter
func (f *Filter) GetStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	if f.mapMgr != nil {
		stats["blocked_ips"] = f.mapMgr.GetBlockedCount()
	}

	stats["interface"] = f.ifaceName

	return stats, nil
}

// getInterface retrieves the network interface by name
func getInterface(name string) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Name == name {
			return &iface, nil
		}
	}

	return nil, fmt.Errorf("interface %s not found", name)
}
