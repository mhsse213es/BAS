package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	server := flag.String("server", "", "target orchestrator base URL, e.g. https://staging.example.com:9443")
	agents := flag.Int("agents", 100, "total simulated fleet size")
	rampPerSec := flag.Int("ramp-rate", 10, "agents enrolled per second during ramp-up")
	duration := flag.Duration("duration", 5*time.Minute, "how long to hold steady-state after ramp-up completes")
	heartbeat := flag.Duration("heartbeat", 30*time.Second, "per-agent heartbeat interval")
	executionLatency := flag.Duration("execution-latency", 3*time.Second, "fake-execution sleep duration per dispatched scenario")
	resultSize := flag.Int("result-size", 512, "approximate size in bytes of each fake step result's Stdout field")
	disconnectRate := flag.Float64("disconnect-rate", 0, "fraction (0.0-1.0) of heartbeat intervals that trigger a forced WS reconnect")
	agentSecret := flag.String("agent-secret", "", "shared agent secret, matching the orchestrator's AGENT_SECRET if configured")
	reportInterval := flag.Duration("report-interval", 10*time.Second, "how often to print a metrics snapshot")
	flag.Parse()

	if *server == "" {
		fmt.Fprintln(os.Stderr, "loadgen: -server is required")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() { <-sigCh; log.Println("[loadgen] interrupt received, shutting down..."); cancel() }()

	metrics := NewMetrics()

	go func() {
		ticker := time.NewTicker(*reportInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				log.Printf("[loadgen] %s", metrics.Snapshot())
			}
		}
	}()

	var wg sync.WaitGroup
	rampDelay := time.Second / time.Duration(*rampPerSec)
	for i := 0; i < *agents; i++ {
		select {
		case <-ctx.Done():
			goto steadyState
		default:
		}
		cfg := simConfig{
			ServerURL:        *server,
			AgentSecret:      *agentSecret,
			AgentID:          fmt.Sprintf("loadgen-%06d", i),
			Hostname:         fmt.Sprintf("LOADGEN-%06d", i),
			Heartbeat:        *heartbeat,
			ExecutionLatency: *executionLatency,
			ResultSizeBytes:  *resultSize,
			DisconnectRate:   *disconnectRate,
		}
		agent := newSimulatedAgent(cfg, metrics)
		wg.Add(1)
		go func() { defer wg.Done(); agent.run(ctx) }()
		time.Sleep(rampDelay)
	}

steadyState:
	log.Printf("[loadgen] ramp complete, holding steady-state for %s", *duration)
	select {
	case <-ctx.Done():
	case <-time.After(*duration):
		cancel()
	}

	wg.Wait()
	log.Printf("[loadgen] final: %s", metrics.Snapshot())
}
