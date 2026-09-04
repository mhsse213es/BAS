package observability

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sync"
	"time"
)

// ProfileRequest specifies what profile to collect.
type ProfileRequest struct {
	// Type is one of: cpu, heap, goroutine, threadcreate, block, mutex
	Type string

	// DurationSeconds is how long to collect (CPU/trace only), 0 means snapshot
	DurationSeconds int
}

// ProfileResult contains the collected profile data.
type ProfileResult struct {
	Type           string
	CollectedAt    time.Time
	DurationMs     int64
	Data           []byte // Raw pprof binary or text output
	Summary        string // Human-readable summary
}

// Profiler handles on-demand CPU and memory profiling.
type Profiler struct {
	mu sync.Mutex
}

// NewProfiler creates a new profiler.
func NewProfiler() *Profiler {
	return &Profiler{}
}

// Collect gathers a profile based on the request.
func (p *Profiler) Collect(ctx context.Context, req *ProfileRequest) (*ProfileResult, error) {
	if req == nil {
		return nil, fmt.Errorf("profile request cannot be nil")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	switch req.Type {
	case "cpu":
		return p.collectCPUProfile(ctx, req)
	case "heap":
		return p.collectHeapProfile()
	case "goroutine":
		return p.collectGoroutineProfile()
	case "threadcreate":
		return p.collectThreadProfile()
	case "block":
		return p.collectBlockProfile()
	case "mutex":
		return p.collectMutexProfile()
	case "trace":
		return p.collectTrace(ctx, req)
	default:
		return nil, fmt.Errorf("unknown profile type: %s", req.Type)
	}
}

// collectCPUProfile captures CPU profile for the requested duration.
func (p *Profiler) collectCPUProfile(ctx context.Context, req *ProfileRequest) (*ProfileResult, error) {
	if req.DurationSeconds <= 0 {
		req.DurationSeconds = 30 // Default 30 seconds
	}

	buf := &bytes.Buffer{}
	if err := pprof.StartCPUProfile(buf); err != nil {
		return nil, fmt.Errorf("failed to start CPU profile: %w", err)
	}

	// Wait for duration (respecting context cancellation)
	select {
	case <-time.After(time.Duration(req.DurationSeconds) * time.Second):
	case <-ctx.Done():
		pprof.StopCPUProfile()
		return nil, ctx.Err()
	}

	pprof.StopCPUProfile()

	return &ProfileResult{
		Type:        "cpu",
		CollectedAt: time.Now(),
		DurationMs: int64(req.DurationSeconds * 1000),
		Data:        buf.Bytes(),
		Summary:     fmt.Sprintf("CPU profile collected for %d seconds", req.DurationSeconds),
	}, nil
}

// collectHeapProfile captures current heap memory usage.
func (p *Profiler) collectHeapProfile() (*ProfileResult, error) {
	var buf bytes.Buffer
	if err := pprof.WriteHeapProfile(&buf); err != nil {
		return nil, fmt.Errorf("failed to write heap profile: %w", err)
	}

	// Get summary stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	summary := fmt.Sprintf("Heap: %d MB alloc, %d MB total, %d MB system, %d goroutines",
		m.Alloc/1024/1024,
		m.TotalAlloc/1024/1024,
		m.Sys/1024/1024,
		runtime.NumGoroutine())

	return &ProfileResult{
		Type:        "heap",
		CollectedAt: time.Now(),
		Data:        buf.Bytes(),
		Summary:     summary,
	}, nil
}

// collectGoroutineProfile captures current goroutine stacks.
func (p *Profiler) collectGoroutineProfile() (*ProfileResult, error) {
	var buf bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&buf, 2); err != nil {
		return nil, fmt.Errorf("failed to write goroutine profile: %w", err)
	}

	summary := fmt.Sprintf("%d goroutines running", runtime.NumGoroutine())

	return &ProfileResult{
		Type:        "goroutine",
		CollectedAt: time.Now(),
		Data:        buf.Bytes(),
		Summary:     summary,
	}, nil
}

// collectThreadProfile captures OS thread creation counts.
func (p *Profiler) collectThreadProfile() (*ProfileResult, error) {
	var buf bytes.Buffer
	if err := pprof.Lookup("threadcreate").WriteTo(&buf, 0); err != nil {
		return nil, fmt.Errorf("failed to write threadcreate profile: %w", err)
	}

	return &ProfileResult{
		Type:        "threadcreate",
		CollectedAt: time.Now(),
		Data:        buf.Bytes(),
		Summary:     "OS thread creation profile",
	}, nil
}

// collectBlockProfile captures goroutine blocking events.
func (p *Profiler) collectBlockProfile() (*ProfileResult, error) {
	var buf bytes.Buffer
	if err := pprof.Lookup("block").WriteTo(&buf, 0); err != nil {
		return nil, fmt.Errorf("failed to write block profile: %w", err)
	}

	return &ProfileResult{
		Type:        "block",
		CollectedAt: time.Now(),
		Data:        buf.Bytes(),
		Summary:     "Goroutine blocking profile",
	}, nil
}

// collectMutexProfile captures lock contention.
func (p *Profiler) collectMutexProfile() (*ProfileResult, error) {
	var buf bytes.Buffer
	if err := pprof.Lookup("mutex").WriteTo(&buf, 0); err != nil {
		return nil, fmt.Errorf("failed to write mutex profile: %w", err)
	}

	return &ProfileResult{
		Type:        "mutex",
		CollectedAt: time.Now(),
		Data:        buf.Bytes(),
		Summary:     "Mutex contention profile",
	}, nil
}

// collectTrace captures a Go trace for the requested duration.
func (p *Profiler) collectTrace(ctx context.Context, req *ProfileRequest) (*ProfileResult, error) {
	if req.DurationSeconds <= 0 {
		req.DurationSeconds = 5 // Default 5 seconds for trace
	}

	buf := &bytes.Buffer{}
	if err := trace.Start(buf); err != nil {
		return nil, fmt.Errorf("failed to start trace: %w", err)
	}

	// Wait for duration
	select {
	case <-time.After(time.Duration(req.DurationSeconds) * time.Second):
	case <-ctx.Done():
		trace.Stop()
		return nil, ctx.Err()
	}

	trace.Stop()

	return &ProfileResult{
		Type:        "trace",
		CollectedAt: time.Now(),
		DurationMs: int64(req.DurationSeconds * 1000),
		Data:        buf.Bytes(),
		Summary:     fmt.Sprintf("Execution trace captured for %d seconds", req.DurationSeconds),
	}, nil
}
