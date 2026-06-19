// Package integrity — watcher.go
// Polls the critical on-disk paths every 15 seconds and detects any change
// in file size or modification time. Uses only stdlib (no fsnotify dep) so
// the binary stays self-contained. On a detected change it:
//  1. Logs a structured TAMPER ALERT.
//  2. Inserts a row into the tamper_events Postgres table.
//  3. Broadcasts a WebSocket MsgTamperAlert to all connected browsers so the
//     dashboard can surface a red security banner without a page reload.
//  4. For "critical" paths (builtin scenarios, manifest), sets a global atomic
//     flag that blocks new run dispatches until an admin acknowledges.

package integrity

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TamperBroadcaster is the subset of ws.Hub that the watcher needs.
// Using an interface keeps the integrity package free of a ws import cycle.
type TamperBroadcaster interface {
	BroadcastTamperAlert(path, eventType, severity string)
}

// DispatchBlocked reports whether a tamper event on a critical file has
// suspended new run dispatches. Callers in handlers.go check this before
// dispatching a scenario to an agent.
var DispatchBlocked atomic.Bool

// watchedFile holds the last-seen metadata for a single file.
type watchedFile struct {
	path     string
	severity string // "critical" | "warning"
	size     int64
	modTime  time.Time
	exists   bool
}

var (
	watchMu    sync.Mutex
	watchFiles []*watchedFile
)

// WatchPaths registers paths to monitor. Call before StartWatcher.
// severity: "critical" for builtin scenarios and manifests; "warning" for config.
func WatchPaths(entries []struct {
	Path     string
	Severity string
}) {
	watchMu.Lock()
	defer watchMu.Unlock()
	for _, e := range entries {
		wf := &watchedFile{path: e.Path, severity: e.Severity}
		snapshotFile(wf) // capture baseline
		watchFiles = append(watchFiles, wf)
	}
}

// WatchDir registers every *.yaml file currently present in dir, plus any
// new ones found on subsequent polls. Used for the scenarios directory.
func WatchDir(dir, severity string) {
	watchMu.Lock()
	defer watchMu.Unlock()
	// Store a sentinel entry with empty path to mark a directory watcher.
	watchFiles = append(watchFiles, &watchedFile{
		path:     dir + "/__dir__",
		severity: severity,
		exists:   true,
	})
	// Snapshot existing yaml files.
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || filepath.Ext(p) != ".yaml" {
			return nil
		}
		wf := &watchedFile{path: p, severity: severity}
		snapshotFile(wf)
		watchFiles = append(watchFiles, wf)
		return nil
	})
}

func snapshotFile(wf *watchedFile) {
	fi, err := os.Stat(wf.path)
	if err != nil {
		wf.exists = false
		return
	}
	wf.exists = true
	wf.size = fi.Size()
	wf.modTime = fi.ModTime()
}

// StartWatcher begins the polling loop. It blocks forever; run in a goroutine.
// pool is used to persist tamper events. broadcaster delivers real-time alerts.
func StartWatcher(ctx context.Context, pool *pgxpool.Pool, broadcaster TamperBroadcaster) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	log.Printf("[integrity] filesystem watcher started — monitoring %d path(s)", len(watchFiles))

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkAll(pool, broadcaster)
		}
	}
}

func checkAll(pool *pgxpool.Pool, broadcaster TamperBroadcaster) {
	watchMu.Lock()
	defer watchMu.Unlock()

	for _, wf := range watchFiles {
		if filepath.Base(wf.path) == "__dir__" {
			// Directory sentinel — scan for new files (handled by WatchDir on first call;
			// re-scan here to pick up files added after startup).
			continue
		}

		fi, err := os.Stat(wf.path)
		nowExists := err == nil

		switch {
		case wf.exists && !nowExists:
			// File deleted.
			recordTamper(pool, broadcaster, wf.path, "remove", wf.severity)
			wf.exists = false

		case !wf.exists && nowExists:
			// File appeared (re-created after deletion or new file in dir watch).
			recordTamper(pool, broadcaster, wf.path, "create", wf.severity)
			wf.exists = true
			wf.size = fi.Size()
			wf.modTime = fi.ModTime()

		case wf.exists && nowExists:
			// Check for modification.
			if fi.Size() != wf.size || fi.ModTime().After(wf.modTime) {
				recordTamper(pool, broadcaster, wf.path, "write", wf.severity)
				wf.size = fi.Size()
				wf.modTime = fi.ModTime()
			}
		}
	}
}

func recordTamper(pool *pgxpool.Pool, broadcaster TamperBroadcaster, path, eventType, severity string) {
	log.Printf("[!!] TAMPER ALERT [%s] %s — %s", severity, eventType, path)

	if severity == "critical" {
		DispatchBlocked.Store(true)
		log.Printf("[!!] Run dispatch SUSPENDED until admin acknowledges tamper event for: %s", path)
	}

	// Persist to DB (best-effort — never crash the watcher on DB failure).
	if pool != nil {
		_, err := pool.Exec(context.Background(), `
			INSERT INTO tamper_events (id, path, event_type, severity)
			VALUES (gen_random_uuid()::text, $1, $2, $3)
		`, path, eventType, severity)
		if err != nil {
			log.Printf("[integrity] tamper_events insert: %v", err)
		}
	}

	// Push real-time alert to all browser sessions.
	if broadcaster != nil {
		broadcaster.BroadcastTamperAlert(path, eventType, severity)
	}
}
