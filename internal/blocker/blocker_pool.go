package blocker

import (
	"context"
	"runtime"

	"github.com/google/gopacket"
)

// WorkerPoolConfig configures the worker pool for packet processing
type WorkerPoolConfig struct {
	// MaxWorkers is the maximum number of concurrent packet processors
	// Recommended: runtime.NumCPU() * 2 for I/O-bound workloads
	// Set to 0 to disable worker pool (unlimited goroutines, default behavior)
	MaxWorkers int

	// QueueSize is the buffered channel size for pending packets
	// Recommended: MaxWorkers * 4 to absorb traffic bursts
	// Larger values use more memory but handle spikes better
	QueueSize int
}

// DefaultWorkerPoolConfig returns recommended worker pool settings
func DefaultWorkerPoolConfig() WorkerPoolConfig {
	cpus := runtime.NumCPU()
	return WorkerPoolConfig{
		MaxWorkers: cpus * 2, // 2× CPU cores (good for I/O-bound packet processing)
		QueueSize:  cpus * 8, // 8× CPU cores (4× workers, absorbs bursts)
	}
}

// WorkerPool manages concurrent packet processing with bounded concurrency
type WorkerPool struct {
	config WorkerPoolConfig
	jobs   chan packetJob
	sem    chan struct{} // Semaphore for concurrency control
}

// packetJob represents a packet processing task
type packetJob struct {
	packet gopacket.Packet
	iface  string
}

// NewWorkerPool creates a worker pool for packet processing
// If config.MaxWorkers is 0, returns nil (disabled, use unlimited goroutines)
func NewWorkerPool(config WorkerPoolConfig) *WorkerPool {
	if config.MaxWorkers <= 0 {
		return nil // Disabled: use unlimited goroutines (current behavior)
	}

	return &WorkerPool{
		config: config,
		jobs:   make(chan packetJob, config.QueueSize),
		sem:    make(chan struct{}, config.MaxWorkers),
	}
}

// Start begins the worker pool (must be called before Submit)
func (wp *WorkerPool) Start(ctx context.Context, b *Blocker) {
	if wp == nil {
		return // Pool disabled
	}

	// Worker loop: process jobs from queue
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case job := <-wp.jobs:
				// Acquire semaphore slot (blocks if pool full)
				wp.sem <- struct{}{}

				// Process packet in background
				go func(j packetJob) {
					defer func() { <-wp.sem }() // Release slot
					b.processPacket(j.packet, j.iface)
				}(job)
			}
		}
	}()
}

// Submit enqueues a packet for processing
// Returns false if queue is full (packet dropped)
func (wp *WorkerPool) Submit(packet gopacket.Packet, iface string) bool {
	if wp == nil {
		return false // Pool disabled, caller should use direct goroutine
	}

	job := packetJob{packet: packet, iface: iface}

	select {
	case wp.jobs <- job:
		return true // Enqueued successfully
	default:
		return false // Queue full, packet dropped
	}
}

// Stats returns worker pool statistics
type WorkerPoolStats struct {
	MaxWorkers    int
	ActiveWorkers int
	QueuedPackets int
	QueueCapacity int
	QueueUtilPct  float64
}

// Stats returns current worker pool statistics
func (wp *WorkerPool) Stats() WorkerPoolStats {
	if wp == nil {
		return WorkerPoolStats{}
	}

	activeWorkers := len(wp.sem)
	queuedPackets := len(wp.jobs)

	return WorkerPoolStats{
		MaxWorkers:    wp.config.MaxWorkers,
		ActiveWorkers: activeWorkers,
		QueuedPackets: queuedPackets,
		QueueCapacity: wp.config.QueueSize,
		QueueUtilPct:  float64(queuedPackets) / float64(wp.config.QueueSize) * 100,
	}
}
