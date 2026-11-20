// Package mysqlaudit reads the Percona audit_log JSON file on the LAB HOST.
//
// It is harness code. Only the harness imports it. The agent never reads the audit
// file, and agent-reported notes never establish plugin state or coverage.
package mysqlaudit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Event is one audit record from the Percona audit_log file.
type Event struct {
	Time      time.Time
	Principal string
	Statement string
	Source    string
}

const sourceName = "percona_audit_log"

type record struct {
	AuditRecord struct {
		Name      string `json:"name"`
		Timestamp string `json:"timestamp"`
		SQLText   string `json:"sqltext"`
		User      string `json:"user"`
	} `json:"audit_record"`
}

// ReadEvents parses one audit_log JSON record per line and returns only the
// Query records. Any malformed line is an error that names its line number:
// a partial read must never look like a complete one.
func ReadEvents(r io.Reader) ([]Event, error) {
	var out []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("audit file line %d: %w", n, err)
		}
		if rec.AuditRecord.Name != "Query" {
			continue
		}
		ts, err := time.Parse(time.RFC3339, rec.AuditRecord.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("audit file line %d: bad timestamp: %w", n, err)
		}
		out = append(out, Event{
			Time:      ts,
			Principal: principalOf(rec.AuditRecord.User),
			Statement: rec.AuditRecord.SQLText,
			Source:    sourceName,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading audit file: %w", err)
	}
	return out, nil
}

// FilterByMarker keeps the events whose statement carries the probe marker.
func FilterByMarker(events []Event, marker string) []Event {
	var out []Event
	for _, e := range events {
		if strings.Contains(e.Statement, marker) {
			out = append(out, e)
		}
	}
	return out
}

// principalOf turns "root[root] @  [127.0.0.1]" into "root".
func principalOf(user string) string {
	if i := strings.IndexByte(user, '['); i >= 0 {
		user = user[:i]
	}
	return strings.TrimSpace(user)
}
