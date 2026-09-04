package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

type ExecutionTrace struct {
	ExecutionID string
	Timestamps  map[string]time.Time
}

func parseLogFile(filename string) (map[string]*ExecutionTrace, error) {
	result := make(map[string]*ExecutionTrace)
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Pattern: [perf] execution_id=run-abc/task-1/attempt-1 poll_selected_at=2026-09-04T12:01:00.001Z
	re := regexp.MustCompile(`\[perf\]\s+execution_id=([^\s]+)\s+([a-z_]+)=(.+)$`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		execID := matches[1]
		stageName := matches[2]
		timestampStr := matches[3]

		if _, exists := result[execID]; !exists {
			result[execID] = &ExecutionTrace{
				ExecutionID: execID,
				Timestamps:  make(map[string]time.Time),
			}
		}

		ts, err := time.Parse(time.RFC3339Nano, timestampStr)
		if err != nil {
			continue
		}

		result[execID].Timestamps[stageName] = ts
	}

	return result, scanner.Err()
}

type StageLatency struct {
	Name      string
	Durations []time.Duration
	Count     int
}

func calculateLatencies(traces map[string]*ExecutionTrace) map[string]*StageLatency {
	result := make(map[string]*StageLatency)

	stages := []struct {
		name  string
		from  string
		to    string
	}{
		{"selection→dispatch", "poll_selected_at", "dispatch_sent_at"},
		{"dispatch→result", "dispatch_sent_at", "result_received_at"},
		{"result→scoring", "result_received_at", "scoring_completed_at"},
		{"selection→scoring", "poll_selected_at", "scoring_completed_at"},
	}

	for _, stage := range stages {
		result[stage.name] = &StageLatency{Name: stage.name, Durations: []time.Duration{}}
	}

	for _, trace := range traces {
		for _, stage := range stages {
			from, hasFrom := trace.Timestamps[stage.from]
			to, hasTo := trace.Timestamps[stage.to]
			if hasFrom && hasTo && to.After(from) {
				latency := to.Sub(from)
				result[stage.name].Durations = append(result[stage.name].Durations, latency)
				result[stage.name].Count++
			}
		}
	}

	return result
}

func percentile(durations []time.Duration, p float64) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	index := int(float64(len(durations)) * p / 100)
	if index >= len(durations) {
		index = len(durations) - 1
	}
	return durations[index]
}

func printLatencyTable(latencies map[string]*StageLatency) {
	fmt.Println("=== Performance Latency Analysis ===\n")
	fmt.Printf("%-25s %12s %12s %12s %8s\n", "Stage", "P50 (ms)", "P95 (ms)", "P99 (ms)", "Count")
	fmt.Println(strings.Repeat("-", 75))

	for _, stageName := range []string{"selection→dispatch", "dispatch→result", "result→scoring", "selection→scoring"} {
		stage := latencies[stageName]
		if stage.Count == 0 {
			continue
		}

		p50 := percentile(stage.Durations, 50)
		p95 := percentile(stage.Durations, 95)
		p99 := percentile(stage.Durations, 99)

		fmt.Printf("%-25s %12.1f %12.1f %12.1f %8d\n",
			stage.Name,
			float64(p50.Milliseconds()),
			float64(p95.Milliseconds()),
			float64(p99.Milliseconds()),
			stage.Count,
		)
	}
}

func main() {
	logFile := flag.String("log", "", "Path to orchestrator log file")
	flag.Parse()

	if *logFile == "" {
		log.Fatal("Usage: parse-perf -log=<logfile>")
	}

	traces, err := parseLogFile(*logFile)
	if err != nil {
		log.Fatalf("Failed to parse log file: %v", err)
	}

	if len(traces) == 0 {
		log.Fatal("No execution traces found in log")
	}

	latencies := calculateLatencies(traces)
	printLatencyTable(latencies)

	fmt.Printf("\nAnalyzed %d executions\n", len(traces))
}
