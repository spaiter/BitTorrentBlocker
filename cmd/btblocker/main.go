package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/example/BitTorrentBlocker/internal/blocker"
)

func main() {
	// Create blocker with default configuration
	config := blocker.DefaultConfig()

	btBlocker, err := blocker.New(config)
	if err != nil {
		log.Fatalf("Failed to create blocker: %v", err)
	}
	defer btBlocker.Close()

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the blocker
	if err := btBlocker.Start(ctx); err != nil {
		log.Fatalf("Failed to start blocker: %v", err)
	}

	log.Println("BitTorrent Blocker (Go + nDPI + SOCKS Unwrap) Started...")
	log.Printf("Configuration: Queue=%d, EntropyThreshold=%.2f, MinPayload=%d",
		config.QueueNum, config.EntropyThreshold, config.MinPayloadSize)

	// Wait for interrupt signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
}
