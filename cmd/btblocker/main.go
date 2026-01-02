package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/example/BitTorrentBlocker/internal/blocker"
)

// Version information (set at build time via ldflags)
var (
	Version = "0.5.1"
	Commit  = "dev"
	Date    = "unknown"
)

func main() {
	// Define flags
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	// Handle version flag
	if *showVersion {
		fmt.Printf("btblocker version %s\n", Version)
		fmt.Printf("  commit: %s\n", Commit)
		fmt.Printf("  built:  %s\n", Date)
		os.Exit(0)
	}
	// Create blocker with default configuration
	config := blocker.DefaultConfig()

	// Override with environment variables if set
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		config.LogLevel = logLevel
	}
	if iface := os.Getenv("INTERFACE"); iface != "" {
		config.Interface = iface
	}

	btBlocker, err := blocker.New(config)
	if err != nil {
		log.Fatalf("Failed to create blocker: %v", err)
	}
	defer btBlocker.Close()

	log.Println("BitTorrent Blocker (Passive Monitoring) Started...")
	log.Printf("Configuration: Interface=%s, EntropyThreshold=%.2f, MinPayload=%d",
		config.Interface, config.EntropyThreshold, config.MinPayloadSize)

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Wait for interrupt signal in a goroutine
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Start blocker (blocking)
	go func() {
		if err := btBlocker.Start(ctx); err != nil && err != context.Canceled {
			log.Fatalf("Failed to start blocker: %v", err)
		}
	}()

	<-sig
	log.Println("Shutting down...")
	cancel()
}
