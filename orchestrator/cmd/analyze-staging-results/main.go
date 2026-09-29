package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"
)

// RunResult is the orchestrator's run response.
type RunResult struct {
	RunID      string    `json:"runId"`
	ScenarioID string    `json:"scenarioId"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"createdAt"`
	StartedAt  time.Time `json:"startedAt"`
	EndedAt    time.Time `json:"endedAt"`
}

// ExecutionMetrics holds computed timing data.
type ExecutionMetrics struct {
	RunID              string
	QueueWait          time.Duration // CreatedAt → StartedAt
	ExecutionDuration  time.Duration // StartedAt → EndedAt
	TotalDuration      time.Duration // CreatedAt → EndedAt
}

// Config holds analysis parameters.
type Config struct {
	OrchestratorURL string
	RunIDs          []string
}

func main() {
	var runsFile string
	flag.StringVar(&runsFile, "url", "http://localhost:8080", "Orchestrator base URL")
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Println("Usage: analyze-staging-results [-url URL] <runId1> <runId2> ...")
		fmt.Println("\nAnalyzes orchestrator run results to measure:")
		fmt.Println("  - Queue wait time (CreatedAt → StartedAt)")
		fmt.Println("  - Execution duration (StartedAt → EndedAt)")
		fmt.Println("  - Total duration (CreatedAt → EndedAt)")
		fmt.Println("\nOutputs timing statistics to identify scheduler serialization.")
		return
	}

	cfg := &Config{
		OrchestratorURL: runsFile,
		RunIDs:          flag.Args(),
	}

	fmt.Printf("Analyzing %d run(s) from %s\n\n", len(cfg.RunIDs), cfg.OrchestratorURL)

	metrics := fetchAndAnalyzeRuns(cfg)
	if len(metrics) == 0 {
		fmt.Println("No results to analyze")
		return
	}

	reportMetrics(metrics)
	identifySerializationPattern(metrics)
}

func fetchAndAnalyzeRuns(cfg *Config) []*ExecutionMetrics {
	var results []*ExecutionMetrics

	for _, runID := range cfg.RunIDs {
		result, err := fetchRun(cfg.OrchestratorURL, runID)
		if err != nil {
			fmt.Printf("Error fetching run %s: %v\n", runID, err)
			continue
		}

		metrics := &ExecutionMetrics{
			RunID:             runID,
			QueueWait:         result.StartedAt.Sub(result.CreatedAt),
			ExecutionDuration: result.EndedAt.Sub(result.StartedAt),
			TotalDuration:     result.EndedAt.Sub(result.CreatedAt),
		}
		results = append(results, metrics)
	}

	return results
}

func fetchRun(baseURL, runID string) (*RunResult, error) {
	resp, err := http.Get(fmt.Sprintf("%s/api/runs/%s", baseURL, runID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}

	var result RunResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func reportMetrics(metrics []*ExecutionMetrics) {
	// Sort by queue wait time to identify patterns
	sortedByQueue := make([]*ExecutionMetrics, len(metrics))
	copy(sortedByQueue, metrics)
	sort.Slice(sortedByQueue, func(i, j int) bool {
		return sortedByQueue[i].QueueWait < sortedByQueue[j].QueueWait
	})

	fmt.Println("Individual Run Metrics:")
	fmt.Println("RunID\t\t\t\t\tQueue Wait\tExecution\tTotal")
	for _, m := range sortedByQueue {
		fmt.Printf("%s\t%v\t%v\t%v\n",
			truncateID(m.RunID),
			m.QueueWait.Milliseconds(),
			m.ExecutionDuration.Milliseconds(),
			m.TotalDuration.Milliseconds(),
		)
	}

	// Calculate statistics
	fmt.Println("\n=== Queue Wait Time Analysis ===")
	reportStats("Queue Wait (ms)", extractQueueWaits(metrics))

	fmt.Println("\n=== Execution Duration Analysis ===")
	reportStats("Execution (ms)", extractExecutionDurations(metrics))

	fmt.Println("\n=== Total Duration Analysis ===")
	reportStats("Total (ms)", extractTotalDurations(metrics))
}

func identifySerializationPattern(metrics []*ExecutionMetrics) {
	fmt.Println("\n=== Scheduler Serialization Check ===")

	// If queue wait times are high and sequential, scheduler is serializing
	waits := extractQueueWaits(metrics)
	if len(waits) > 1 {
		sort.Slice(waits, func(i, j int) bool { return waits[i] < waits[j] })

		maxWait := waits[len(waits)-1]
		minWait := waits[0]

		serialization := float64(maxWait.Milliseconds()) / float64(minWait.Milliseconds())

		fmt.Printf("Queue Wait Range: %vms → %vms (ratio: %.1fx)\n",
			minWait.Milliseconds(), maxWait.Milliseconds(), serialization)

		if serialization > 2.0 {
			fmt.Println("⚠️  High serialization detected: Queue waits are increasing non-uniformly")
			fmt.Println("   This suggests scheduler may be processing jobs sequentially")
		} else {
			fmt.Println("✓ Uniform queue waits: Scheduler appears to be handling jobs in parallel")
		}
	}
}

func reportStats(label string, durations []time.Duration) {
	if len(durations) == 0 {
		return
	}

	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })

	sum := sumDurations(durations)
	avg := sum / time.Duration(len(durations))
	p50 := durations[len(durations)/2]
	p95 := durations[(len(durations)*95)/100]
	p99 := durations[(len(durations)*99)/100]

	fmt.Printf("%s:\n", label)
	fmt.Printf("  Count:  %d\n", len(durations))
	fmt.Printf("  Avg:    %vms\n", avg.Milliseconds())
	fmt.Printf("  Min/Max: %vms / %vms\n", durations[0].Milliseconds(), durations[len(durations)-1].Milliseconds())
	fmt.Printf("  P50:    %vms\n", p50.Milliseconds())
	fmt.Printf("  P95:    %vms\n", p95.Milliseconds())
	fmt.Printf("  P99:    %vms\n", p99.Milliseconds())
}

func extractQueueWaits(metrics []*ExecutionMetrics) []time.Duration {
	var waits []time.Duration
	for _, m := range metrics {
		waits = append(waits, m.QueueWait)
	}
	return waits
}

func extractExecutionDurations(metrics []*ExecutionMetrics) []time.Duration {
	var execs []time.Duration
	for _, m := range metrics {
		execs = append(execs, m.ExecutionDuration)
	}
	return execs
}

func extractTotalDurations(metrics []*ExecutionMetrics) []time.Duration {
	var totals []time.Duration
	for _, m := range metrics {
		totals = append(totals, m.TotalDuration)
	}
	return totals
}

func sumDurations(durations []time.Duration) time.Duration {
	var sum time.Duration
	for _, d := range durations {
		sum += d
	}
	return sum
}

func truncateID(id string) string {
	if len(id) > 16 {
		return id[:16]
	}
	return id
}
