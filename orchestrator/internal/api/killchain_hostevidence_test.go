package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/killchain"
	"github.com/audspect/bas/internal/scenario"
)

type fakeHostEvents struct {
	events []killchain.HostEvent
	audit  killchain.AuditState
	win    db.HostEventWindow
	found  bool
	err    error
}

func (f fakeHostEvents) HostEventsForRun(context.Context, string) ([]killchain.HostEvent, killchain.AuditState, db.HostEventWindow, bool, error) {
	return f.events, f.audit, f.win, f.found, f.err
}

type fakeHostNames struct{ name string }

func (f fakeHostNames) AgentHostname(context.Context, string) (string, error) { return f.name, nil }

type fakeScenarios map[string]*scenario.Scenario

func (f fakeScenarios) Get(id string) (*scenario.Scenario, bool) {
	sc, ok := f[id]
	return sc, ok
}

var hostWin = db.HostEventWindow{
	From: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC),
	To:   time.Date(2026, 10, 20, 9, 10, 0, 0, time.UTC),
}

func markedScenario(id, marker string) *scenario.Scenario {
	return &scenario.Scenario{ID: id, Steps: []scenario.Step{{TechniqueID: "T1", Command: "run " + marker, Marker: marker}}}
}

func markerEvent(id uint64, cmd string) killchain.HostEvent {
	return killchain.HostEvent{RecordID: id, EventID: 4688, Host: "WS-01",
		Time: hostWin.From.Add(time.Minute), NewProcess: "powershell.exe", CommandLine: cmd}
}

func collectWithHost(sid string, hosts fakeHostEvents, scen fakeScenarios) (killchain.StageEvidence, error) {
	x := EngineStageExecutor{
		Runs: fakeRuns{snap: runSnapshot{ExecutionID: "run-h", ScenarioID: sid, AgentID: "a1", Status: "completed",
			CompletedAt: hostWin.To}},
		HostEvents: hosts,
		Hosts:      fakeHostNames{name: "WS-01"},
		Scenarios:  scen,
	}
	ev, _, _, err := x.Collect(context.Background(), "run-h")
	return ev, err
}

// A completed run with the marker in a process creation record in the window is
// execution evidence, with the 4688 reference kept.
func TestHostEvidence_MatchingMarkerRecordsExecution(t *testing.T) {
	ev, err := collectWithHost("credential-access",
		fakeHostEvents{events: []killchain.HostEvent{markerEvent(7, "run bas-cred-ident-01")}, found: true,
			win: hostWin, audit: killchain.AuditState{ProcessCreation: killchain.AuditEnabled, Logon: killchain.AuditEnabled, CommandLine: killchain.AuditEnabled}},
		fakeScenarios{"credential-access": markedScenario("credential-access", "bas-cred-ident-01")})
	if err != nil {
		t.Fatal(err)
	}
	if ev.GroundTruth.Executed != killchain.TriYes || ev.GroundTruth.Reference != "WS-01:7:4688" {
		t.Fatalf("ground truth = %+v", ev.GroundTruth)
	}
}

// A scenario with no marker has no host evidence to read, so nothing is recorded.
func TestHostEvidence_NoMarkerNoEvidence(t *testing.T) {
	ev, err := collectWithHost("credential-access",
		fakeHostEvents{events: []killchain.HostEvent{markerEvent(7, "run bas-cred-ident-01")}, found: true, win: hostWin},
		fakeScenarios{"credential-access": {ID: "credential-access", Steps: []scenario.Step{{TechniqueID: "T1", Command: "x"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if ev.GroundTruth.Executed != "" {
		t.Fatalf("executed = %q, want missing", ev.GroundTruth.Executed)
	}
}

// Host evidence is only used for a scenario whose policy accepts event logs.
func TestHostEvidence_ScenarioWithoutPolicyIsNotRead(t *testing.T) {
	ev, err := collectWithHost("scn-unpolicied",
		fakeHostEvents{events: []killchain.HostEvent{markerEvent(7, "run bas-cred-ident-01")}, found: true, win: hostWin},
		fakeScenarios{"scn-unpolicied": markedScenario("scn-unpolicied", "bas-cred-ident-01")})
	if err != nil {
		t.Fatal(err)
	}
	if ev.GroundTruth.Executed != "" {
		t.Fatalf("a scenario with no source policy must not take host evidence")
	}
}

// No batch for the run means nothing is read, and nothing is assumed.
func TestHostEvidence_NoBatchIsNotAssumed(t *testing.T) {
	ev, err := collectWithHost("credential-access", fakeHostEvents{found: false},
		fakeScenarios{"credential-access": markedScenario("credential-access", "bas-cred-ident-01")})
	if err != nil {
		t.Fatal(err)
	}
	if ev.GroundTruth.Executed != "" {
		t.Fatalf("executed = %q, want missing", ev.GroundTruth.Executed)
	}
}

// A read failure is retryable. It is not recorded as no evidence.
func TestHostEvidence_ReadErrorIsRetryable(t *testing.T) {
	x := EngineStageExecutor{
		Runs: fakeRuns{snap: runSnapshot{ExecutionID: "run-h", ScenarioID: "credential-access", AgentID: "a1", Status: "completed"}},
		HostEvents: fakeHostEvents{err: errors.New("db down")},
		Hosts:      fakeHostNames{name: "WS-01"},
		Scenarios:  fakeScenarios{"credential-access": markedScenario("credential-access", "bas-cred-ident-01")},
	}
	_, done, failed, err := x.Collect(context.Background(), "run-h")
	if err == nil || done || failed {
		t.Fatalf("done=%v failed=%v err=%v; a read error must be retryable", done, failed, err)
	}
}

// A manual ground-truth record takes precedence over host evidence.
func TestHostEvidence_ManualRecordWins(t *testing.T) {
	x := EngineStageExecutor{
		Runs: fakeRuns{snap: runSnapshot{ExecutionID: "run-h", ScenarioID: "credential-access", AgentID: "a1", Status: "completed"}},
		GroundTruth: fakeGT{found: true, rec: db.GroundTruthRecord{Source: "operator-recorded", Executed: killchain.TriNo, Reference: "ticket-1"}},
		HostEvents: fakeHostEvents{events: []killchain.HostEvent{markerEvent(7, "run bas-cred-ident-01")}, found: true, win: hostWin},
		Hosts:      fakeHostNames{name: "WS-01"},
		Scenarios:  fakeScenarios{"credential-access": markedScenario("credential-access", "bas-cred-ident-01")},
	}
	ev, _, _, err := x.Collect(context.Background(), "run-h")
	if err != nil {
		t.Fatal(err)
	}
	if ev.GroundTruth.Source != "operator-recorded" || ev.GroundTruth.Executed != killchain.TriNo {
		t.Fatalf("manual record lost to host evidence: %+v", ev.GroundTruth)
	}
}
