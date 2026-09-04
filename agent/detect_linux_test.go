//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These exercise the real file-reading path -- tailFile, the path layout and
// the source-precedence rules -- against a temporary root, so they run on any
// Linux host without touching the machine's own /var/log.

func writeUnder(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

func TestCollectAuditdIn_ReadsRealFile(t *testing.T) {
	root := t.TempDir()
	writeUnder(t, root, auditLogPath, auditSample)
	from, to := auditWindow()
	recs := collectAuditdIn(root, from, to)
	if len(recs) != 2 {
		t.Fatalf("want 2 records from the audit log, got %d", len(recs))
	}
	if recs[0].Provider != "curl" {
		t.Errorf("Provider = %q, want curl", recs[0].Provider)
	}
}

// A host with no auditd must yield nothing rather than an error. It also must
// not fall through to a stale ausearch result -- absence of the file is the
// honest answer that the source was not available.
func TestCollectAuditdIn_MissingFileYieldsNothing(t *testing.T) {
	from, to := auditWindow()
	if recs := collectAuditdIn(t.TempDir(), from, to); len(recs) != 0 {
		t.Fatalf("want no records from an empty root, got %d", len(recs))
	}
}

func TestCollectSyslogFilesIn_ReadsFirstMatch(t *testing.T) {
	root := t.TempDir()
	writeUnder(t, root, "var/log/syslog", syslogSample)
	from := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	recs := collectSyslogFilesIn(root, from, to)
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	if recs[0].Channel != syslogChannel {
		t.Errorf("Channel = %q, want %q", recs[0].Channel, syslogChannel)
	}
}

// The first path that merely EXISTS must not end the search. An empty
// /var/log/syslog alongside a populated /var/log/messages is ordinary on a
// mixed host, and stopping at the empty one would report no evidence.
func TestCollectSyslogFilesIn_SkipsEmptyAndContinues(t *testing.T) {
	root := t.TempDir()
	writeUnder(t, root, "var/log/syslog", "")
	writeUnder(t, root, "var/log/messages", syslogSample)
	from := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	if recs := collectSyslogFilesIn(root, from, to); len(recs) != 2 {
		t.Fatalf("want 2 records from the second path, got %d", len(recs))
	}
}

// tailFile must return the END of an oversized file: the run window always
// concerns the newest records, and reading the head would return the oldest.
func TestTailFile_ReturnsTailAndFlagsTruncation(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "big.log")
	head := make([]byte, 4096)
	for i := range head {
		head[i] = 'A'
	}
	if err := os.WriteFile(p, append(head, []byte("TAILMARKER\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	b, truncated, err := tailFile(p, 64)
	if err != nil {
		t.Fatalf("tailFile: %v", err)
	}
	if !truncated {
		t.Error("want truncated=true for a file larger than the limit")
	}
	if got := string(b); len(got) > 64 || !strings.Contains(got, "TAILMARKER") {
		t.Errorf("want the tail of the file within 64 bytes, got %q", got)
	}
}

// A whole run's collection must survive every source being absent. This is the
// container / minimal-host case, and it must report "we found nothing", never
// crash and never report a detection.
func TestCollectAlerts_EmptyHostIsNotAnError(t *testing.T) {
	from := time.Now().Add(-time.Minute)
	to := time.Now()
	recs, truncated := collectAlerts(from, to, 10, 1024)
	if truncated {
		t.Error("truncated must be false when nothing was collected")
	}
	for _, r := range recs {
		if r.ThreatName != "" {
			t.Errorf("collected a ThreatName from a live host: %q", r.ThreatName)
		}
	}
}
