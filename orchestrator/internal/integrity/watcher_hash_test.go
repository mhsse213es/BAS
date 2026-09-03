package integrity

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// resetWatch clears the package-level watch list so each test starts clean.
func resetWatch(t *testing.T) {
	t.Helper()
	watchMu.Lock()
	prev := watchFiles
	watchFiles = nil
	watchMu.Unlock()
	t.Cleanup(func() {
		watchMu.Lock()
		watchFiles = prev
		watchMu.Unlock()
	})
}

// recorder captures tamper broadcasts instead of sending them to browsers.
type recorder struct{ events []string }

func (r *recorder) BroadcastTamperAlert(path, eventType, severity string) {
	r.events = append(r.events, eventType+":"+severity+":"+filepath.Base(path))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// A size- and mtime-preserving edit must still be detected.
//
// The watcher compared os.Stat size and ModTime only, so an edit that kept the
// byte count and restored the timestamp (touch -r) was invisible. For scenario
// files the RSA signature still catches that at load, but BINARIES.sha256 and
// the licence had the stat comparison as their ONLY protection.
func TestWatcher_DetectsSameSizeSameMtimeEdit(t *testing.T) {
	resetWatch(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "BINARIES.sha256")
	writeFile(t, path, "AAAA")

	WatchPaths([]struct {
		Path     string
		Severity string
	}{{Path: path, Severity: "critical"}})

	// Capture the original timestamp, edit in place with identical length, then
	// restore the timestamp — the classic evasion.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	writeFile(t, path, "BBBB") // same size, different content
	if err := os.Chtimes(path, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	after, _ := os.Stat(path)
	if after.Size() != fi.Size() || !after.ModTime().Equal(fi.ModTime()) {
		t.Fatalf("test setup failed to preserve size/mtime: size %d->%d, mtime %v->%v",
			fi.Size(), after.Size(), fi.ModTime(), after.ModTime())
	}

	rec := &recorder{}
	checkAll(nil, rec)

	if len(rec.events) == 0 {
		t.Error("a content change with identical size and mtime was not detected")
	}
}

// The common case must still work.
func TestWatcher_DetectsOrdinaryEdit(t *testing.T) {
	resetWatch(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "index.html")
	writeFile(t, path, "<html>original</html>")

	WatchPaths([]struct {
		Path     string
		Severity string
	}{{Path: path, Severity: "critical"}})

	time.Sleep(10 * time.Millisecond)
	writeFile(t, path, "<html>tampered, and longer</html>")

	rec := &recorder{}
	checkAll(nil, rec)

	if len(rec.events) != 1 {
		t.Fatalf("events = %v, want exactly one write event", rec.events)
	}
	if rec.events[0] != "write:critical:index.html" {
		t.Errorf("event = %q, want write:critical:index.html", rec.events[0])
	}
}

// An untouched file must never alert. A watcher that cried wolf every poll
// would be turned off, which is worse than not having one.
func TestWatcher_UnchangedFileIsSilent(t *testing.T) {
	resetWatch(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "licence.lic")
	writeFile(t, path, "licence-body")

	WatchPaths([]struct {
		Path     string
		Severity string
	}{{Path: path, Severity: "critical"}})

	rec := &recorder{}
	checkAll(nil, rec)
	checkAll(nil, rec) // twice — a stable file must stay silent across polls

	if len(rec.events) != 0 {
		t.Errorf("unchanged file produced events: %v", rec.events)
	}
}

// Deletion and re-creation must still be reported, and re-creation must
// re-baseline so the next poll is silent rather than alerting forever.
func TestWatcher_DetectsDeleteThenRecreate(t *testing.T) {
	resetWatch(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "index.html")
	writeFile(t, path, "original")

	WatchPaths([]struct {
		Path     string
		Severity string
	}{{Path: path, Severity: "critical"}})

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	rec := &recorder{}
	checkAll(nil, rec)
	if len(rec.events) != 1 || rec.events[0] != "remove:critical:index.html" {
		t.Fatalf("after delete, events = %v, want one remove", rec.events)
	}

	writeFile(t, path, "replaced")
	checkAll(nil, rec)
	if len(rec.events) != 2 || rec.events[1] != "create:critical:index.html" {
		t.Fatalf("after recreate, events = %v, want a create", rec.events)
	}

	checkAll(nil, rec)
	if len(rec.events) != 2 {
		t.Errorf("a re-created file must re-baseline; got repeat events: %v", rec.events)
	}
}
