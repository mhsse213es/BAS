package wafmodsec

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// auditLogTimeLayout is ModSecurity's own SecAuditLogFormat JSON
// time_stamp layout -- a bare ctime() string with no timezone
// designator ("Tue Nov 10 07:54:32 2026"), confirmed by reading a real
// audit record produced by the running lab container. The container's
// own clock is UTC (confirmed via `docker exec ... date`), so this is
// parsed as UTC, not the host's local zone.
const auditLogTimeLayout = time.ANSIC

// AuditLogEntry is the subset of one ModSecurity JSON audit-log
// transaction this package actually uses: enough to prove a given test
// request was recorded, and when. TimeStamp carries only second
// precision -- the audit log format itself has none -- so callers that
// compare it against a sub-second time.Now() must truncate that value
// to the same precision first, or a real near-instant write can appear
// to precede its own triggering event.
type AuditLogEntry struct {
	TimeStamp time.Time
	UniqueID  string
}

type auditLogLine struct {
	Transaction struct {
		TimeStamp string `json:"time_stamp"`
		UniqueID  string `json:"unique_id"`
		Request   struct {
			URI string `json:"uri"`
		} `json:"request"`
	} `json:"transaction"`
}

// FindAuditLogEntry scans a ModSecurity SecAuditLogFormat JSON audit log
// (one JSON object per line -- confirmed empirically against the real
// lab container: multiple requests produce multiple newline-delimited
// lines, never a single concatenated document) for the most recent
// transaction whose request URI contains marker, returning (entry, true,
// nil) if found. A missing file is the lab's normal startup state before
// ModSecurity has written its first relevant transaction, not an error:
// it returns (zero value, false, nil), same as a file that exists but
// has no matching line.
func FindAuditLogEntry(path string, marker string) (AuditLogEntry, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return AuditLogEntry{}, false, nil
		}
		return AuditLogEntry{}, false, fmt.Errorf("opening audit log %q: %w", path, err)
	}
	defer f.Close()

	var found AuditLogEntry
	ok := false
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if !strings.Contains(string(line), marker) {
			continue
		}
		var parsed auditLogLine
		if err := json.Unmarshal(line, &parsed); err != nil {
			continue
		}
		if !strings.Contains(parsed.Transaction.Request.URI, marker) {
			continue
		}
		ts, err := time.ParseInLocation(auditLogTimeLayout, parsed.Transaction.TimeStamp, time.UTC)
		if err != nil {
			continue
		}
		found = AuditLogEntry{TimeStamp: ts, UniqueID: parsed.Transaction.UniqueID}
		ok = true
	}
	if err := scanner.Err(); err != nil {
		return AuditLogEntry{}, false, fmt.Errorf("scanning audit log %q: %w", path, err)
	}
	return found, ok, nil
}
