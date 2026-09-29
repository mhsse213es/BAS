package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// RunRequest matches the orchestrator's API run submission payload.
type RunRequest struct {
	ScenarioID string `json:"scenarioId"`
}

// RunResponse is the orchestrator's run creation response.
type RunResponse struct {
	RunID string `json:"runId"`
}

// JobTiming captures per-job execution timeline.
type JobTiming struct {
	JobNum          int
	SubmitTime      time.Time
	SubmitCompleted time.Time
	SubmitLatency   time.Duration
	RunID           string
	Err             error
}

// Config holds test parameters.
type Config struct {
	OrchestratorURL string
	ScenarioID      string
	Concurrency     int
	Repetitions     int
	Delay           time.Duration
}

func main() {
	cfg := &Config{}
	flag.StringVar(&cfg.OrchestratorURL, "url", "http://localhost:8080", "Orchestrator base URL")
	flag.StringVar(&cfg.ScenarioID, "scenario", "", "Scenario ID to run")
	flag.IntVar(&cfg.Concurrency, "concurrency", 5, "Number of parallel jobs")
	flag.IntVar(&cfg.Repetitions, "reps", 1, "Repetitions per concurrency level")
	flag.DurationVar(&cfg.Delay, "delay", 0, "Delay between job submissions")
	flag.Parse()

	if cfg.ScenarioID == "" {
		fmt.Println("Error: -scenario required")
		flag.PrintDefaults()
		return
	}

	fmt.Printf("Staging Load Test Configuration\n")
	fmt.Printf("  Orchestrator: %s\n", cfg.OrchestratorURL)
	fmt.Printf("  Scenario: %s\n", cfg.ScenarioID)
	fmt.Printf("  Concurrency: %d jobs/wave\n", cfg.Concurrency)
	fmt.Printf("  Repetitions: %d waves\n", cfg.Repetitions)
	fmt.Printf("  Submission delay: %v between jobs\n\n", cfg.Delay)

	// Run test waves
	for rep := 1; rep <= cfg.Repetitions; rep++ {
		fmt.Printf("=== Wave %d of %d ===\n", rep, cfg.Repetitions)
		timings := runConcurrentWave(cfg, rep)
		reportWaveResults(timings)
		fmt.Println()
	}
}

func runConcurrentWave(cfg *Config, waveNum int) []*JobTiming {
	timings := make([]*JobTiming, cfg.Concurrency)
	wg := &sync.WaitGroup{}
	wg.Add(cfg.Concurrency)

	waveStart := time.Now()

	for i := 1; i <= cfg.Concurrency; i++ {
		go func(jobNum int) {
			defer wg.Done()

			timing := &JobTiming{JobNum: jobNum}
			timing.SubmitTime = time.Now()

			runID, err := submitRun(cfg)
			timing.SubmitCompleted = time.Now()
			timing.SubmitLatency = timing.SubmitCompleted.Sub(timing.SubmitTime)
			timing.RunID = runID
			timing.Err = err

			timings[jobNum-1] = timing

			if cfg.Delay > 0 && jobNum < cfg.Concurrency {
				time.Sleep(cfg.Delay)
			}
		}(i)
	}

	wg.Wait()
	waveEnd := time.Now()
	fmt.Printf("Wave %d completed in %v\n", waveNum, waveEnd.Sub(waveStart))

	return timings
}

func submitRun(cfg *Config) (string, error) {
	req := &RunRequest{ScenarioID: cfg.ScenarioID}
	payload, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(
		cfg.OrchestratorURL+"/api/runs",
		"application/json",
		bytes.NewReader(payload),
	)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("submission failed: status %d: %s", resp.StatusCode, body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var runResp RunResponse
	if err := json.Unmarshal(body, &runResp); err != nil {
		return "", err
	}

	return runResp.RunID, nil
}

func reportWaveResults(timings []*JobTiming) {
	var successCount int
	var totalLatency time.Duration
	var minLatency, maxLatency time.Duration

	minLatency = time.Hour // large initial value
	for _, t := range timings {
		if t.Err != nil {
			fmt.Printf("  Job %d: ERROR - %v\n", t.JobNum, t.Err)
			continue
		}
		successCount++
		totalLatency += t.SubmitLatency
		if t.SubmitLatency < minLatency {
			minLatency = t.SubmitLatency
		}
		if t.SubmitLatency > maxLatency {
			maxLatency = t.SubmitLatency
		}
		fmt.Printf("  Job %d: %v (Run: %s)\n", t.JobNum, t.SubmitLatency, t.RunID)
	}

	if successCount == 0 {
		fmt.Println("No successful submissions")
		return
	}

	avgLatency := totalLatency / time.Duration(successCount)
	fmt.Printf("\nWave Stats:\n")
	fmt.Printf("  Success: %d/%d\n", successCount, len(timings))
	fmt.Printf("  Avg submission latency: %v\n", avgLatency)
	fmt.Printf("  Min/Max: %v / %v\n", minLatency, maxLatency)
}
