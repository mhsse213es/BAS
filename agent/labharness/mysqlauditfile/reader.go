// Package mysqlauditfile reads the Percona audit_log JSON file on the LAB HOST.
//
// It is lab-harness code. The agent binary must never import it: the agent does
// not access the audit file. The harness reads the file and supplies the parsed
// events to the BAS tests as evidence.
package mysqlauditfile

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"audspect/agent/dbprobe"
)

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
func ReadEvents(r io.Reader) ([]dbprobe.AuditEvent, error) {
	var out []dbprobe.AuditEvent
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
		out = append(out, dbprobe.AuditEvent{
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
func FilterByMarker(events []dbprobe.AuditEvent, marker string) []dbprobe.AuditEvent {
	var out []dbprobe.AuditEvent
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
