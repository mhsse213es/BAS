package killchain

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// AuditSetting is the state of one Windows audit subcategory on a host.
type AuditSetting string

const (
	AuditEnabled  AuditSetting = "enabled"
	AuditDisabled AuditSetting = "disabled"
	AuditUnknown  AuditSetting = ""
)

// AuditState records the audit subcategories that the Security events depend on.
type AuditState struct {
	ProcessCreation AuditSetting // Security 4688
	Logon           AuditSetting // Security 4624 and 4648
}

// HostEvent is one Windows Security event from a host. Only the fields the
// evaluator uses are kept.
type HostEvent struct {
	RecordID    uint64
	EventID     int
	Host        string
	Time        time.Time
	Subject     string
	NewProcess  string // 4688 NewProcessName
	CommandLine string // 4688 CommandLine, present only when command-line capture is configured
	LogonType   int    // 4624
	TargetUser  string // 4624 and 4648
}

// ExecutionMatch identifies the step to prove. The marker is a token the step puts
// in its command line. Matching requires the marker, the host, and the window. A
// timestamp alone is never enough.
type ExecutionMatch struct {
	Marker      string
	Host        string
	WindowStart time.Time
	WindowEnd   time.Time
}

// HostFinding is what the host events establish for one step. Executed is yes
// only with a matching process-creation event. It is never no. Absence is always a
// gap.
type HostFinding struct {
	Executed   Tri
	Evidence   []string // process-creation references proving execution, as host:recordID:eventID
	Supporting []string // logon and credential evidence. It does not prove execution.
	Gaps       []string // what is missing or unreliable, and why an absence is not a no
}

// EvaluateHostEvents turns a step's host events into a finding. Duplicate records
// count once. A record id that appears with different content is a conflict, and
// neither copy is trusted.
func EvaluateHostEvents(m ExecutionMatch, events []HostEvent, audit AuditState) HostFinding {
	var f HostFinding
	unique, conflicts := dedupeHostEvents(events)
	for _, c := range conflicts {
		f.Gaps = append(f.Gaps, fmt.Sprintf("conflicting records for %s:%d:%d; neither copy is trusted", c.Host, c.RecordID, c.EventID))
	}
	for _, ev := range unique {
		if !strings.EqualFold(ev.Host, m.Host) || ev.Time.Before(m.WindowStart) || ev.Time.After(m.WindowEnd) {
			continue
		}
		switch ev.EventID {
		case 4688:
			if containsFold(ev.CommandLine, m.Marker) || containsFold(ev.NewProcess, m.Marker) {
				f.Evidence = append(f.Evidence, fmt.Sprintf("%s:%d:%d", ev.Host, ev.RecordID, ev.EventID))
			}
		case 4624:
			if ev.LogonType == 3 || ev.LogonType == 10 {
				f.Supporting = append(f.Supporting, fmt.Sprintf("logon type %d to %s on %s (event %s:%d:%d); supports, does not prove execution",
					ev.LogonType, ev.TargetUser, ev.Host, ev.Host, ev.RecordID, ev.EventID))
			}
		case 4648:
			f.Supporting = append(f.Supporting, fmt.Sprintf("explicit credentials for %s on %s (event %s:%d:%d); supports, does not prove execution",
				ev.TargetUser, ev.Host, ev.Host, ev.RecordID, ev.EventID))
		}
	}
	if hasProcessCreationInWindow(unique, m) && audit.ProcessCreation == AuditDisabled {
		f.Gaps = append(f.Gaps, "inconsistent audit state: process creation auditing reports disabled on "+m.Host+" but process creation records exist; neither is trusted alone")
	}
	if len(f.Evidence) > 0 {
		f.Executed = TriYes
		return f
	}
	switch audit.ProcessCreation {
	case AuditDisabled:
		f.Gaps = append(f.Gaps, fmt.Sprintf("process creation auditing is disabled on %s; no 4688 record is not evidence that the step did not run", m.Host))
	case AuditUnknown:
		f.Gaps = append(f.Gaps, "process creation auditing state is unknown; a missing 4688 record cannot be interpreted")
	default:
		f.Gaps = append(f.Gaps, "no matching process creation event for the step marker in the window; absence is not a result")
	}
	return f
}

// dedupeHostEvents removes identical duplicates and reports record ids that
// appear with different content.
func dedupeHostEvents(events []HostEvent) ([]HostEvent, []HostEvent) {
	type key struct {
		host string
		id   uint64
		ev   int
	}
	seen := map[key]HostEvent{}
	conflicted := map[key]HostEvent{}
	for _, e := range events {
		k := key{strings.ToLower(e.Host), e.RecordID, e.EventID}
		prev, ok := seen[k]
		if !ok {
			seen[k] = e
			continue
		}
		if prev != e {
			conflicted[k] = e
		}
	}
	unique := make([]HostEvent, 0, len(seen))
	for k, e := range seen {
		if _, bad := conflicted[k]; bad {
			continue
		}
		unique = append(unique, e)
	}
	sort.Slice(unique, func(i, j int) bool { return unique[i].RecordID < unique[j].RecordID })
	conflicts := make([]HostEvent, 0, len(conflicted))
	for k, e := range conflicted {
		conflicts = append(conflicts, HostEvent{Host: k.host, RecordID: k.id, EventID: k.ev, Subject: e.Subject})
	}
	return unique, conflicts
}

func containsFold(s, sub string) bool {
	return sub != "" && strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// GroundTruthRecordFor is the ground-truth candidate a host finding can support. It
// is produced only for a process-creation match. The reference is the 4688 record
// that proved it.
type GroundTruthRecordFor struct {
	Source      string
	SourceClass SourceClass
	Executed    Tri
	Reference   string
}

// GroundTruthFromFinding returns a ground-truth candidate only when the finding
// proved execution. A finding with no evidence yields nothing.
func GroundTruthFromFinding(f HostFinding) (GroundTruthRecordFor, bool) {
	if f.Executed != TriYes || len(f.Evidence) == 0 {
		return GroundTruthRecordFor{}, false
	}
	return GroundTruthRecordFor{
		Source:      "Windows Security 4688 (process creation)",
		SourceClass: SourceEventLog,
		Executed:    TriYes,
		Reference:   f.Evidence[0],
	}, true
}

// hasProcessCreationInWindow reports whether any 4688 record for the match host
// falls inside the window, whether or not it carries the marker.
func hasProcessCreationInWindow(events []HostEvent, m ExecutionMatch) bool {
	for _, ev := range events {
		if ev.EventID == 4688 && strings.EqualFold(ev.Host, m.Host) &&
			!ev.Time.Before(m.WindowStart) && !ev.Time.After(m.WindowEnd) {
			return true
		}
	}
	return false
}
