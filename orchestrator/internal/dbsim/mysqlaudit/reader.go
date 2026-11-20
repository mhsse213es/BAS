// Package mysqlaudit is the harness's own reader of the MySQL audit plugin. Only the
// harness imports it. The agent never reads the audit file, and agent-reported notes
// never establish plugin state, coverage or an event.
package mysqlaudit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

const sourceName = "percona_audit_log"

// Event is one Query record from the Percona audit_log file.
type Event struct {
	Time      time.Time
	Principal string
	Statement string
	Source    string
}

// Record is one audit_log record of any kind (Connect, Query, Quit, ...).
type Record struct {
	Name         string
	Time         time.Time
	ConnectionID string
	User         string
	SQLText      string
}

type rawRecord struct {
	AuditRecord struct {
		Name         string `json:"name"`
		Timestamp    string `json:"timestamp"`
		ConnectionID string `json:"connection_id"`
		SQLText      string `json:"sqltext"`
		User         string `json:"user"`
	} `json:"audit_record"`
}

// ParseRecords parses one JSON record per line. A malformed line is an error that
// names its line number, so a partial read never looks complete.
func ParseRecords(r io.Reader) ([]Record, error) {
	var out []Record
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var raw rawRecord
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return nil, fmt.Errorf("audit file line %d: %w", n, err)
		}
		ts, err := time.Parse(time.RFC3339, raw.AuditRecord.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("audit file line %d: bad timestamp: %w", n, err)
		}
		out = append(out, Record{
			Name:         raw.AuditRecord.Name,
			Time:         ts,
			ConnectionID: raw.AuditRecord.ConnectionID,
			User:         principalOf(raw.AuditRecord.User),
			SQLText:      raw.AuditRecord.SQLText,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading audit file: %w", err)
	}
	return out, nil
}

// ReadEvents returns only the Query records, as Events.
func ReadEvents(r io.Reader) ([]Event, error) {
	recs, err := ParseRecords(r)
	if err != nil {
		return nil, err
	}
	var out []Event
	for _, rec := range recs {
		if rec.Name != "Query" {
			continue
		}
		out = append(out, Event{Time: rec.Time, Principal: rec.User, Statement: rec.SQLText, Source: sourceName})
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
