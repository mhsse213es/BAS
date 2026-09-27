package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"audspect/agent/protocol"
)

const (
	logBufferCap     = 500
	logFlushBatch    = 100
	logFlushInterval = 30 * time.Second
	logRetentionDays = 30
)

// LogEvent is the versioned envelope for every event sent to the server and
// written to local log files. All 3 tiers share this structure.
type LogEvent struct {
	SchemaVersion int            `json:"schema_version"`
	EventType     string         `json:"event_type"` // op_log | sec_log | telemetry
	AgentID       string         `json:"agent_id"`
	Seq           uint64         `json:"seq"`
	Ts            time.Time      `json:"ts"`
	Payload       map[string]any `json:"payload"`
}

// Logger provides 3-tier structured logging with local file rotation and
// buffered HTTPS delivery. All methods are safe for concurrent use.
//
// Tiers:
//
//	Op     → operational (lifecycle, connectivity, service management)
//	Sec    → security/scenario (step execution, results, artifacts)
//	Metric → telemetry (latency_ms, cpu_pct, fail_count)
type Logger struct {
	agentID   string
	serverURL string
	secret    string
	client    *http.Client

	seqCounter atomic.Uint64

	bufMu sync.Mutex
	buf   []LogEvent

	fileMu  sync.Mutex
	files   map[string]*os.File
	fileDay map[string]string // eventType → current date "2006-01-02"
}

// NewLogger creates and starts a Logger. Takes the full Config (not just
// ServerURL/AgentSecret) so its client can be built proxy-aware the same
// way newAgent's own client is -- log-shipping is real HTTPS traffic to the
// orchestrator, not local I/O, so it needs the same CONNECT negotiation
// support as every other outbound call.
func NewLogger(cfg Config, agentID string) *Logger {
	l := &Logger{
		agentID:   agentID,
		serverURL: cfg.ServerURL,
		secret:    cfg.AgentSecret,
		client:    &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{DialContext: proxyAwareNetDialContext(cfg), Proxy: nil, TLSClientConfig: agentTLSConfig(cfg)}},
		buf:       make([]LogEvent, 0, logBufferCap),
		files:     make(map[string]*os.File),
		fileDay:   make(map[string]string),
	}
	if err := os.MkdirAll(logDir(), 0755); err != nil {
		log.Printf("[logger] could not create log dir %s: %v", logDir(), err)
	}
	go l.periodicFlush()
	go l.periodicRotate()
	return l
}

// Op logs an operational event (connectivity, lifecycle, service management).
func (l *Logger) Op(level, category, message string) {
	l.emit("op_log", map[string]any{
		"level":    level,
		"category": category,
		"message":  message,
	})
}

// Sec logs a security/scenario event (step execution, result, artifact evidence).
func (l *Logger) Sec(level, scenarioID, runID, stepID, techID, category, message string) {
	l.emit("sec_log", map[string]any{
		"level":        level,
		"scenario_id":  scenarioID,
		"run_id":       runID,
		"step_id":      stepID,
		"technique_id": techID,
		"category":     category,
		"message":      message,
	})
}

// Metric records a single telemetry measurement.
func (l *Logger) Metric(name string, value float64, unit string) {
	l.emit("telemetry", map[string]any{
		"metric": name,
		"value":  value,
		"unit":   unit,
	})
}

func (l *Logger) emit(eventType string, payload map[string]any) {
	evt := LogEvent{
		SchemaVersion: protocol.SchemaVersion,
		EventType:     eventType,
		AgentID:       l.agentID,
		Seq:           l.seqCounter.Add(1),
		Ts:            time.Now().UTC(),
		Payload:       payload,
	}
	l.writeFile(evt)

	l.bufMu.Lock()
	if len(l.buf) >= logBufferCap {
		// Ring: drop oldest when full (WS/server unavailable for a long time)
		l.buf = l.buf[1:]
	}
	l.buf = append(l.buf, evt)
	l.bufMu.Unlock()
}

// writeFile appends the event as a JSON line to the appropriate daily log file.
func (l *Logger) writeFile(evt LogEvent) {
	today := evt.Ts.Format("2006-01-02")
	key := evt.EventType

	l.fileMu.Lock()
	defer l.fileMu.Unlock()

	if l.fileDay[key] != today {
		if f := l.files[key]; f != nil {
			f.Close()
		}
		fname := filepath.Join(logDir(), key+"-"+today+".log")
		f, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
		l.files[key] = f
		l.fileDay[key] = today
	}
	f := l.files[key]
	if f == nil {
		return
	}
	line, _ := json.Marshal(evt)
	f.Write(line)
	f.WriteString("\n")
}

// Flush sends buffered events to the server via the HTTPS batch endpoint.
// Called by the periodic ticker and by connectWS after each reconnect so
// events buffered while offline are delivered as soon as connectivity returns.
func (l *Logger) Flush() {
	l.bufMu.Lock()
	if len(l.buf) == 0 {
		l.bufMu.Unlock()
		return
	}
	n := len(l.buf)
	if n > logFlushBatch {
		n = logFlushBatch
	}
	batch := make([]LogEvent, n)
	copy(batch, l.buf[:n])
	l.bufMu.Unlock()

	body, err := json.Marshal(map[string]any{"events": batch})
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost,
		l.serverURL+"/api/agents/events", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if l.secret != "" {
		req.Header.Set("X-Agent-Token", l.secret)
	}
	resp, err := l.client.Do(req)
	if err != nil {
		return // keep buffer, retry next cycle
	}
	resp.Body.Close()
	if resp.StatusCode < 300 {
		l.bufMu.Lock()
		if len(l.buf) >= n {
			l.buf = l.buf[n:]
		}
		l.bufMu.Unlock()
	}
}

func (l *Logger) periodicFlush() {
	t := time.NewTicker(logFlushInterval)
	defer t.Stop()
	for range t.C {
		l.Flush()
	}
}

// periodicRotate runs once per day and deletes log files older than logRetentionDays.
func (l *Logger) periodicRotate() {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().AddDate(0, 0, -logRetentionDays).Format("2006-01-02")
		entries, err := os.ReadDir(logDir())
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			// filename: {event_type}-{YYYY-MM-DD}.log — date is last 14 chars before ".log"
			if !strings.HasSuffix(name, ".log") || len(name) < 14 {
				continue
			}
			dateStr := name[len(name)-14 : len(name)-4]
			if len(dateStr) == 10 && dateStr < cutoff {
				path := filepath.Join(logDir(), name)
				l.fileMu.Lock()
				// Close the file handle if we have it open (shouldn't be open since it's old)
				for k, f := range l.files {
					if filepath.Base(f.Name()) == name {
						f.Close()
						delete(l.files, k)
						delete(l.fileDay, k)
					}
				}
				l.fileMu.Unlock()
				_ = os.Remove(path)
			}
		}
	}
}

// Infof is a convenience wrapper for Op("info", "general", fmt.Sprintf(...)).
func (l *Logger) Infof(format string, args ...any) {
	l.Op("info", "general", fmt.Sprintf(format, args...))
}

// Warnf is a convenience wrapper for Op("warn", "general", fmt.Sprintf(...)).
func (l *Logger) Warnf(format string, args ...any) {
	l.Op("warn", "general", fmt.Sprintf(format, args...))
}

// Errorf is a convenience wrapper for Op("error", "general", fmt.Sprintf(...)).
func (l *Logger) Errorf(format string, args ...any) {
	l.Op("error", "general", fmt.Sprintf(format, args...))
}
