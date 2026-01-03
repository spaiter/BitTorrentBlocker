package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/example/BitTorrentBlocker/internal/blocker"
)

// Version information (set at build time via ldflags)
var (
	Version = "0.15.0"
	Commit  = "dev"
	Date    = "unknown"
)

// splitAndTrim splits a string by separator and trims whitespace from each part
func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

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
		// Support comma-separated list of interfaces
		config.Interfaces = []string{}
		for _, i := range splitAndTrim(iface, ",") {
			if i != "" {
				config.Interfaces = append(config.Interfaces, i)
			}
		}
	}
	if banDuration := os.Getenv("BAN_DURATION"); banDuration != "" {
		if duration, err := strconv.Atoi(banDuration); err == nil && duration > 0 {
			config.BanDuration = duration
		}
	}
	if detectionLog := os.Getenv("DETECTION_LOG"); detectionLog != "" {
		config.DetectionLogPath = detectionLog
	}
	if monitorOnly := os.Getenv("MONITOR_ONLY"); monitorOnly == "true" || monitorOnly == "1" {
		config.MonitorOnly = true
	}

	btBlocker, err := blocker.New(config)
	if err != nil {
		log.Fatalf("Failed to create blocker: %v", err)
	}
	defer btBlocker.Close()

	log.Println("BitTorrent Blocker (Passive Monitoring) Started...")
	log.Printf("Configuration: Interfaces=%v, BanDuration=%ds",
		config.Interfaces, config.BanDuration)

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
