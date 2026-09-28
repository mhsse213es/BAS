package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"audspect/agent/protocol"
)

// The on-disk spool gives run-result delivery restart-durability. submitRunResult
// persists every result here BEFORE attempting delivery; the drainer ships them to
// the server and deletes each one only after the server has accepted it. So a
// server outage — or a full agent/endpoint restart in the middle of one — can no
// longer lose a completed or partial assessment: it sits on disk until the link
// returns. The payload is a COMPLETE snapshot and the server REPLACES (never
// appends), so re-delivery is idempotent: a retry after a dropped response, or a
// late delivery that reconciles a run the server already flagged 'partial',
// converges to the same final state. See project_run_reconciliation.

const (
	spoolExt           = ".json"
	spoolTmpExt        = ".tmp"
	spoolDrainInterval = 30 * time.Second
)

// spoolDirOverride lets tests redirect the spool away from the system path; empty
// in production, where the platform spoolDir() is used.
var spoolDirOverride string

func resolveSpoolDir() string {
	if spoolDirOverride != "" {
		return spoolDirOverride
	}
	return spoolDir()
}

// spooledResult is the on-disk envelope for a run result awaiting delivery.
type spooledResult struct {
	Label    string                `json:"label"`    // completed|partial|scan — for logging only
	QueuedAt time.Time             `json:"queuedAt"` // when the result was first spooled
	Payload  protocol.RawRunResult `json:"payload"`
}

// spoolFileName maps a run to a stable filename so re-spooling the same run
// overwrites its earlier envelope rather than queuing a duplicate. RunIDs are
// server-issued UUID/hash strings, but sanitize defensively against path traversal.
func spoolFileName(runID string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, runID)
	if safe == "" {
		safe = "unknown"
	}
	return safe + spoolExt
}

// spoolWrite persists a run result to disk atomically (temp file + rename), so a
// crash mid-write can never leave a half-written envelope that the drainer would
// choke on. Returns the path of the persisted file.
func (a *Agent) spoolWrite(payload protocol.RawRunResult, label string) (string, error) {
	dir := resolveSpoolDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	env := spooledResult{Label: label, QueuedAt: time.Now(), Payload: payload}
	data, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	final := filepath.Join(dir, spoolFileName(payload.RunID))
	tmp := final + spoolTmpExt
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return final, nil
}

// drainSpool attempts to deliver every spooled result to the server, deleting each
// only after the server accepts it. Drains are serialized (spoolMu) so a periodic
// tick and a reconnect kick can't double-send. On the first delivery failure it
// stops — the server is unreachable, so there is no point hammering the rest; the
// remaining files wait for the next drain.
func (a *Agent) drainSpool() {
	a.spoolMu.Lock()
	defer a.spoolMu.Unlock()

	dir := resolveSpoolDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[!] spool: cannot read %s: %v", dir, err)
		}
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), spoolExt) {
			continue // skip stray temp files / subdirs
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[!] spool: cannot read %s: %v", path, err)
			continue
		}
		var env spooledResult
		if err := json.Unmarshal(data, &env); err != nil {
			// Corrupt envelope — it will never deliver; drop it so it doesn't wedge
			// the queue forever.
			log.Printf("[x] spool: dropping corrupt envelope %s: %v", path, err)
			os.Remove(path)
			continue
		}
		if err := protocol.SubmitResult(context.Background(), a.httpClient(), a.cfg().ServerURL, a.cfg().AgentSecret, env.Payload); err != nil {
			log.Printf("[!] spool: delivery deferred (%s) run=%s: %v", env.Label, env.Payload.RunID, err)
			return // server unreachable — stop; retry on next drain
		}
		os.Remove(path)
		log.Printf("[+] spool: delivered (%s) run=%s", env.Label, env.Payload.RunID)
	}
}

// runSpoolDrainer is the long-lived delivery loop. It drains once on startup
// (shipping anything left over from a crash or restart), then on a fixed tick and
// whenever a reconnect kicks it.
func (a *Agent) runSpoolDrainer() {
	a.drainSpool()
	t := time.NewTicker(spoolDrainInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			a.drainSpool()
		case <-a.spoolKick:
			a.drainSpool()
		}
	}
}

// kickSpool nudges the drainer to attempt delivery immediately (e.g. right after a
// heartbeat reconnects) instead of waiting for the next tick. Non-blocking: the
// buffered channel coalesces bursts into a single drain.
func (a *Agent) kickSpool() {
	select {
	case a.spoolKick <- struct{}{}:
	default:
	}
}
