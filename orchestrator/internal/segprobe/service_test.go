package segprobe

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/audspect/bas/internal/segprobe/runstore"
)

const testScenarioDir = "../../../lab/segmentation/scenarios"

// memStore is an in-memory RunStore.
type memStore struct {
	mu          sync.Mutex
	runs        map[string]*runstore.Run
	rows        map[string][]runstore.ProbeRow
	createCalls int
	n           int
}

func newMemStore() *memStore {
	return &memStore{runs: map[string]*runstore.Run{}, rows: map[string][]runstore.ProbeRow{}}
}

func (m *memStore) Create(_ context.Context, packID, requestedBy string) (runstore.Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createCalls++
	m.n++
	r := &runstore.Run{ID: string(rune('a'+m.n)) + "-run", PackID: packID, RequestedBy: requestedBy, Status: "queued"}
	m.runs[r.ID] = r
	return *r, nil
}

func (m *memStore) SetRunning(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[id].Status = "running"
	return nil
}

func (m *memStore) SaveRunResults(_ context.Context, id string, _ int, rows []runstore.ProbeRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[id] = append(m.rows[id], rows...)
	return nil
}

func (m *memStore) Finish(_ context.Context, id, status string, runs int, stable *bool, failure string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs[id]
	r.Status, r.Runs, r.Stable, r.FailureReason = status, runs, stable, failure
	return nil
}

func (m *memStore) get(id string) runstore.Run {
	m.mu.Lock()
	defer m.mu.Unlock()
	return *m.runs[id]
}

// labFake is a LabProvider whose probes cannot reach any zone, so every probe
// grades ERROR. ERROR is a stored verdict, so a run still completes.
type labFake struct {
	fakeProvider
	applyErr error
	block    chan struct{}
	applied  []string
}

func (l *labFake) ApplyRules(_ context.Context, rulesFile string) error {
	if l.block != nil {
		<-l.block
	}
	l.applied = append(l.applied, rulesFile)
	return l.applyErr
}

func unreachable() *labFake {
	return &labFake{fakeProvider: fakeProvider{healthyErr: map[Zone]error{ZoneCorp: errors.New("down"), ZoneSWIFT: errors.New("down")}}}
}

func TestService_HappyPathStoresThreePassesAndCompletes(t *testing.T) {
	noGap(t)
	store := newMemStore()
	svc := NewService(store, testScenarioDir, func() LabProvider { return unreachable() })

	run, err := svc.Submit(context.Background(), "swift-isolation", "admin@example.test")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	svc.Wait()

	got := store.get(run.ID)
	if got.Status != "completed" || got.Runs != RunsPerPack || got.Stable == nil || !*got.Stable {
		t.Fatalf("run = %+v", got)
	}
	// swift-isolation has three probes; three passes store nine rows.
	if n := len(store.rows[run.ID]); n != 3*RunsPerPack {
		t.Fatalf("stored %d probe rows, want %d", n, 3*RunsPerPack)
	}
}

func TestService_SecondSubmitWhileBusyIsRefused(t *testing.T) {
	noGap(t)
	store := newMemStore()
	lab := unreachable()
	lab.block = make(chan struct{})
	svc := NewService(store, testScenarioDir, func() LabProvider { return lab })

	if _, err := svc.Submit(context.Background(), "swift-isolation", "admin@example.test"); err != nil {
		t.Fatalf("first Submit: %v", err)
	}
	if _, err := svc.Submit(context.Background(), "cde-atm-isolation", "admin@example.test"); !errors.Is(err, ErrBusy) {
		t.Fatalf("second Submit: got %v, want ErrBusy", err)
	}
	close(lab.block)
	svc.Wait()
}

func TestService_RulesFailureMarksRunFailedWithoutResults(t *testing.T) {
	noGap(t)
	store := newMemStore()
	lab := unreachable()
	lab.applyErr = errors.New("container not running")
	svc := NewService(store, testScenarioDir, func() LabProvider { return lab })

	run, err := svc.Submit(context.Background(), "core-banking-tiering", "admin@example.test")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	svc.Wait()

	got := store.get(run.ID)
	if got.Status != "failed" || !strings.Contains(got.FailureReason, "apply firewall rules") {
		t.Fatalf("run = %+v", got)
	}
	if len(store.rows[run.ID]) != 0 {
		t.Fatalf("results were stored for a run whose rules never applied")
	}
}

func TestService_UnknownPackIsRefusedBeforeAnyRunIsRecorded(t *testing.T) {
	store := newMemStore()
	svc := NewService(store, testScenarioDir, func() LabProvider { return unreachable() })
	if _, err := svc.Submit(context.Background(), "../../etc/passwd", "admin@example.test"); !errors.Is(err, ErrUnknownPack) {
		t.Fatalf("got %v, want ErrUnknownPack", err)
	}
	if store.createCalls != 0 {
		t.Fatal("a run row was created for an unregistered pack")
	}
}

func TestToProbeRows_KeepsVerdictReasonAndRuleIDs(t *testing.T) {
	pass := RunResult{RunIndex: 2, Outcomes: []ProbeOutcome{{
		Spec:    ProbeSpec{ID: "corp-to-db", Src: ZoneCorp, Dst: ZoneDB, DstPort: 5432, Proto: "tcp", Expect: ExpectDeny},
		Verdict: PASS,
		Reason:  "blocked with firewall evidence (SEG-DENY-DB-1)",
		Result:  ProbeResult{Outcome: OutcomeTimeout},
		Events:  []FirewallEvent{{RuleID: "SEG-DENY-DB-1", Action: "DROP"}},
	}}}
	rows := toProbeRows(pass)
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.RunIndex != 2 || r.Verdict != "PASS" || r.Expect != "deny" || r.Outcome != "timeout" ||
		len(r.RuleIDs) != 1 || r.RuleIDs[0] != "SEG-DENY-DB-1" || r.StartedAt != nil {
		t.Fatalf("row = %+v", r)
	}
}
