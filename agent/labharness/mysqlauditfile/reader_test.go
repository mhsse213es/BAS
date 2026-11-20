package mysqlauditfile

import (
	"strings"
	"testing"
	"time"
)

const queryLine = `{"audit_record":{"name":"Query","record":"1_2026-11-20T11:00:00","timestamp":"2026-11-20T11:00:00Z","command_class":"select","connection_id":"43","status":0,"sqltext":"SELECT /* dbsim:audit-verify-002 */ 1","user":"root[root] @  [127.0.0.1]","host":"","os_user":"","ip":"127.0.0.1","db":""}}`

const pingLine = `{"audit_record":{"name":"Ping","record":"2_2026-11-20T11:00:01","timestamp":"2026-11-20T11:00:01Z","command_class":"ping","connection_id":"43","status":0,"sqltext":"","user":"root[root] @  [127.0.0.1]","host":"","ip":"127.0.0.1","db":""}}`

func TestReadEventsReturnsQueryRecordsOnly(t *testing.T) {
	events, err := ReadEvents(strings.NewReader(pingLine + "\n" + queryLine + "\n"))
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 Query event, got %d", len(events))
	}
	e := events[0]
	if e.Statement != "SELECT /* dbsim:audit-verify-002 */ 1" {
		t.Errorf("statement: got %q", e.Statement)
	}
	if e.Principal != "root" {
		t.Errorf("principal: want root (host part stripped), got %q", e.Principal)
	}
	want, _ := time.Parse(time.RFC3339, "2026-11-20T11:00:00Z")
	if !e.Time.Equal(want) {
		t.Errorf("time: got %v want %v", e.Time, want)
	}
	if e.Source != "percona_audit_log" {
		t.Errorf("source: got %q", e.Source)
	}
}

func TestReadEventsEmptyFileIsNotAnError(t *testing.T) {
	events, err := ReadEvents(strings.NewReader(""))
	if err != nil || len(events) != 0 {
		t.Fatalf("empty file: events=%d err=%v", len(events), err)
	}
}

func TestReadEventsMalformedLineFailsClosed(t *testing.T) {
	_, err := ReadEvents(strings.NewReader(queryLine + "\n{not json\n"))
	if err == nil {
		t.Fatal("a malformed line must be an error, not silently skipped (evidence would be incomplete)")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error should name the line: %v", err)
	}
}

func TestFilterByMarkerMatchesOnlyTaggedStatements(t *testing.T) {
	events, err := ReadEvents(strings.NewReader(queryLine + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := FilterByMarker(events, "dbsim:audit-verify-002"); len(got) != 1 {
		t.Errorf("tagged marker: want 1, got %d", len(got))
	}
	if got := FilterByMarker(events, "dbsim:audit-verify-999"); len(got) != 0 {
		t.Errorf("untagged marker: want 0, got %d", len(got))
	}
}
