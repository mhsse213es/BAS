package wafmodsec

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const sampleAuditLine = `{"transaction":{"client_ip":"172.18.0.1","time_stamp":"Tue Nov 10 07:54:32 2026","server_id":"x","client_port":1,"host_ip":"172.18.0.3","host_port":8080,"unique_id":"179429727246.135523","is_interrupted":true,"request":{"method":"GET","http_version":"1.1","hostname":"localhost","uri":"/search?q=%27%20UNION%20SELECT%20NULL--%20MARKER123","headers":{}}}}` + "\n"

func TestFindAuditLogEntry_MatchingMarkerPresent_ReturnsEntryFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte(sampleAuditLine), 0o644); err != nil {
		t.Fatalf("writing fixture audit log: %v", err)
	}

	entry, found, err := FindAuditLogEntry(path, "MARKER123")
	if err != nil {
		t.Fatalf("FindAuditLogEntry: %v", err)
	}
	if !found {
		t.Fatal("found = false, want true")
	}
	wantTime := time.Date(2026, time.November, 10, 7, 54, 32, 0, time.UTC)
	if !entry.TimeStamp.Equal(wantTime) {
		t.Errorf("TimeStamp = %v, want %v", entry.TimeStamp, wantTime)
	}
	if entry.UniqueID != "179429727246.135523" {
		t.Errorf("UniqueID = %q, want %q", entry.UniqueID, "179429727246.135523")
	}
}

func TestFindAuditLogEntry_MarkerAbsent_ReturnsNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte(sampleAuditLine), 0o644); err != nil {
		t.Fatalf("writing fixture audit log: %v", err)
	}

	_, found, err := FindAuditLogEntry(path, "NO_SUCH_MARKER")
	if err != nil {
		t.Fatalf("FindAuditLogEntry: %v", err)
	}
	if found {
		t.Error("found = true, want false")
	}
}

func TestFindAuditLogEntry_FileDoesNotExist_ReturnsNotFoundNoError(t *testing.T) {
	// The lab's audit log file is created by ModSecurity only once it
	// has written its first relevant transaction -- a bind-mounted,
	// not-yet-written file is the normal startup state, not an error.
	_, found, err := FindAuditLogEntry(filepath.Join(t.TempDir(), "never-written.log"), "MARKER123")
	if err != nil {
		t.Fatalf("FindAuditLogEntry: %v", err)
	}
	if found {
		t.Error("found = true, want false")
	}
}
