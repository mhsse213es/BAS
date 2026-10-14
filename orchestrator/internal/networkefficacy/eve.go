package networkefficacy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"
)

// eveRecord is the subset of Suricata's EVE JSON schema this parser
// cares about. Suricata emits many more fields and event types; only
// "alert" events are kept, since those are this phase's IDS/IPS
// evidence.
type eveRecord struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	Alert     *struct {
		Signature string `json:"signature"`
		Severity  int    `json:"severity"`
	} `json:"alert,omitempty"`
}

// ParseSuricataEVE reads newline-delimited Suricata EVE JSON and
// returns the normalized IDSEvidence for every "alert" event. Any
// other event_type (flow, dns, http, ...) is skipped. A malformed line
// is an error, not a silently dropped record -- collection/parsing
// failure must be distinguishable from "no alerts occurred" by the
// caller (internal/networkefficacy's own VerifyControlExpectation
// relies on this distinction). Source is always SourceFixture: this
// parser's only caller in this phase is a recorded fixture file, never
// a live stream (deferred per the spec §8).
func ParseSuricataEVE(r io.Reader) ([]IDSEvidence, error) {
	var out []IDSEvidence
	scanner := bufio.NewScanner(r)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec eveRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("networkefficacy: eve line %d: %w", lineNum, err)
		}
		if rec.EventType != "alert" || rec.Alert == nil {
			continue
		}
		ts, err := time.Parse("2006-01-02T15:04:05.999999-0700", rec.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("networkefficacy: eve line %d: invalid timestamp %q: %w", lineNum, rec.Timestamp, err)
		}
		out = append(out, IDSEvidence{
			SourceIP:  rec.SrcIP,
			DestIP:    rec.DestIP,
			Port:      rec.DestPort,
			Protocol:  rec.Proto,
			AlertName: rec.Alert.Signature,
			Severity:  strconv.Itoa(rec.Alert.Severity),
			Timestamp: ts,
			Source:    SourceFixture,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("networkefficacy: eve scan: %w", err)
	}
	return out, nil
}

// FixtureIDSProvider wraps a slice of already-parsed IDSEvidence (from
// ParseSuricataEVE) and implements IDSEvidenceProvider by filtering to
// the ones matching a flow and time window.
type FixtureIDSProvider struct {
	records []IDSEvidence
}

func NewFixtureIDSProvider(records []IDSEvidence) *FixtureIDSProvider {
	return &FixtureIDSProvider{records: records}
}

func (p *FixtureIDSProvider) IDSEvidenceFor(flow Flow, window TimeWindow) ([]IDSEvidence, error) {
	var out []IDSEvidence
	for _, r := range p.records {
		if !matchesFlow(r.SourceIP, r.DestIP, r.Port, r.Protocol, flow) {
			continue
		}
		if !inWindow(r.Timestamp, window) {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}
