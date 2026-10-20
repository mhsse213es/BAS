package killchain

import (
	"strings"
	"testing"
	"time"
)

var (
	evStart = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	evEnd   = evStart.Add(5 * time.Minute)
)

func match() ExecutionMatch {
	return ExecutionMatch{Marker: "svc-cred-dump-7f3a", Host: "WS-01", WindowStart: evStart, WindowEnd: evEnd}
}

func procEvent(id uint64, cmd string, at time.Time) HostEvent {
	return HostEvent{RecordID: id, EventID: 4688, Host: "WS-01", Time: at,
		NewProcess: `C:\Windows\System32\rundll32.exe`, CommandLine: cmd, Subject: "svc-test"}
}

func auditOn() AuditState { return AuditState{ProcessCreation: AuditEnabled, Logon: AuditEnabled} }

// Present: a 4688 whose command line carries the step's marker in the window
// is positive evidence that the step executed.
func TestHostEvents_PresentProcessCreationProvesExecution(t *testing.T) {
	f := EvaluateHostEvents(match(), []HostEvent{procEvent(101, "rundll32 svc-cred-dump-7f3a", evStart.Add(time.Minute))}, auditOn())
	if f.Executed != TriYes {
		t.Fatalf("executed = %q, want yes", f.Executed)
	}
	if len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0], "WS-01:101:4688") {
		t.Fatalf("evidence = %v, want a reference WS-01:101:4688", f.Evidence)
	}
}

// Missing: with process-creation auditing off, no 4688 is not evidence of
// non-execution. Executed stays unknown and the gap is named.
func TestHostEvents_MissingWithAuditingOffIsAGapNotAbsence(t *testing.T) {
	audit := AuditState{ProcessCreation: AuditDisabled, Logon: AuditEnabled}
	f := EvaluateHostEvents(match(), nil, audit)
	if f.Executed == TriNo || f.Executed == TriYes {
		t.Fatalf("executed = %q; absence with auditing off must stay unknown", f.Executed)
	}
	if !containsReason(f.Gaps, "process creation auditing is disabled") {
		t.Fatalf("gaps = %v, want the disabled audit policy named", f.Gaps)
	}
}

func TestHostEvents_MissingWithAuditingOnIsStillNotNo(t *testing.T) {
	f := EvaluateHostEvents(match(), nil, auditOn())
	if f.Executed == TriNo {
		t.Fatalf("an empty window must never be read as did-not-execute")
	}
	if !containsReason(f.Gaps, "no matching process creation event") {
		t.Fatalf("gaps = %v", f.Gaps)
	}
}

// Duplicated: the same record delivered twice counts once, and cannot be
// mistaken for two executions.
func TestHostEvents_DuplicateRecordCountsOnce(t *testing.T) {
	ev := procEvent(101, "svc-cred-dump-7f3a", evStart.Add(time.Minute))
	f := EvaluateHostEvents(match(), []HostEvent{ev, ev}, auditOn())
	if len(f.Evidence) != 1 {
		t.Fatalf("evidence = %v, want one reference for a duplicated record", f.Evidence)
	}
}

// Contradictory: the same record id with different content is a conflict. Neither
// copy is trusted, so the stage stays unknown.
func TestHostEvents_ContradictoryRecordIsNotTrusted(t *testing.T) {
	a := procEvent(101, "svc-cred-dump-7f3a", evStart.Add(time.Minute))
	b := procEvent(101, "something-else", evStart.Add(time.Minute))
	f := EvaluateHostEvents(match(), []HostEvent{a, b}, auditOn())
	if f.Executed == TriYes {
		t.Fatalf("a conflicting record must not prove execution")
	}
	if !containsReason(f.Gaps, "conflicting") {
		t.Fatalf("gaps = %v, want the conflict named", f.Gaps)
	}
}

// Delayed: an event outside the bounded window does not prove the step, however
// well its marker matches. Correlation uses the window as well as the marker.
func TestHostEvents_EventOutsideWindowDoesNotCount(t *testing.T) {
	late := procEvent(101, "svc-cred-dump-7f3a", evEnd.Add(time.Minute))
	f := EvaluateHostEvents(match(), []HostEvent{late}, auditOn())
	if f.Executed == TriYes {
		t.Fatalf("an event outside the window must not prove execution")
	}
}

// Marker matching is required: a process in the window without the step's marker
// is not this step's execution.
func TestHostEvents_TimestampAloneIsNotCorrelation(t *testing.T) {
	other := procEvent(101, "notepad.exe", evStart.Add(time.Minute))
	f := EvaluateHostEvents(match(), []HostEvent{other}, auditOn())
	if f.Executed == TriYes {
		t.Fatalf("a timestamp match without the marker must not prove execution")
	}
}

// Logon events establish logon-related evidence only. They are reported as such
// and never count as proof that a lateral step executed.
func TestHostEvents_LogonEvidenceDoesNotProveExecution(t *testing.T) {
	logon := HostEvent{RecordID: 900, EventID: 4624, Host: "WS-01", Time: evStart.Add(time.Minute), LogonType: 3, TargetUser: "svc-test"}
	f := EvaluateHostEvents(match(), []HostEvent{logon}, auditOn())
	if f.Executed == TriYes {
		t.Fatalf("a logon event must not prove that a step executed")
	}
	if len(f.Supporting) != 1 || !strings.Contains(f.Supporting[0], "logon type 3") {
		t.Fatalf("supporting = %v, want the logon reported as supporting evidence", f.Supporting)
	}
}

// A different host's events are not this run's evidence.
func TestHostEvents_OtherHostIsIgnored(t *testing.T) {
	ev := procEvent(101, "svc-cred-dump-7f3a", evStart.Add(time.Minute))
	ev.Host = "WS-99"
	f := EvaluateHostEvents(match(), []HostEvent{ev}, auditOn())
	if f.Executed == TriYes {
		t.Fatalf("an event from another host must not prove execution")
	}
}

func containsReason(list []string, want string) bool {
	for _, s := range list {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}

// Only a process-creation match can become a ground-truth record. Absence and
// logon evidence produce none, so they cannot be recorded as executed or not.
func TestGroundTruthFromFinding_OnlyProcessCreationBecomesRecord(t *testing.T) {
	yes := EvaluateHostEvents(match(), []HostEvent{procEvent(101, "svc-cred-dump-7f3a", evStart.Add(time.Minute))}, auditOn())
	gt, ok := GroundTruthFromFinding(yes)
	if !ok || gt.Executed != TriYes || gt.Reference != "WS-01:101:4688" || gt.SourceClass != SourceEventLog {
		t.Fatalf("ground truth = %+v ok=%v", gt, ok)
	}

	none := EvaluateHostEvents(match(), nil, auditOn())
	if _, ok := GroundTruthFromFinding(none); ok {
		t.Fatalf("an absence must not become a ground-truth record")
	}
	logon := EvaluateHostEvents(match(), []HostEvent{{RecordID: 9, EventID: 4624, Host: "WS-01", Time: evStart.Add(time.Minute), LogonType: 3}}, auditOn())
	if _, ok := GroundTruthFromFinding(logon); ok {
		t.Fatalf("a logon must not become an executed record")
	}
}

// Audit reporting disabled while process creation records are present is an
// inconsistent state. The evaluator must name it, and it must not pick a side.
func TestHostEvents_AuditDisabledButRecordsPresentIsNamedAsInconsistent(t *testing.T) {
	audit := AuditState{ProcessCreation: AuditDisabled, Logon: AuditEnabled}
	unrelated := procEvent(55, "notepad.exe", evStart.Add(time.Minute))
	f := EvaluateHostEvents(match(), []HostEvent{unrelated}, audit)
	if !containsReason(f.Gaps, "inconsistent") {
		t.Fatalf("gaps = %v, want the inconsistent audit state named", f.Gaps)
	}
	if f.Executed == TriYes {
		t.Fatalf("an unrelated record must not prove execution")
	}
}
