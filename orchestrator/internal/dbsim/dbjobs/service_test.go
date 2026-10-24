package dbjobs

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbadmin"
	"github.com/audspect/bas/internal/scenario"
)

var t0 = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

const agentA = "0123456789abcdef"

// ---- fakes ------------------------------------------------------------------

type fakeTargets struct{ recs map[string]dbsim.TargetRecord }

func (f *fakeTargets) Get(_ context.Context, id string) (dbsim.TargetRecord, error) {
	r, ok := f.recs[id]
	if !ok {
		return dbsim.TargetRecord{}, dbsim.ErrTargetNotFound
	}
	return r, nil
}

type fakeScenarios map[string]*scenario.Scenario

func (f fakeScenarios) Get(id string) (*scenario.Scenario, bool) { s, ok := f[id]; return s, ok }

type auditRow struct {
	Entry dbadmin.AuditEntry
	Job   string
}

type fakeStore struct {
	mu        sync.Mutex
	jobs      map[string]dbsim.RunJob
	audits    []auditRow
	failAudit bool
}

func newStore() *fakeStore { return &fakeStore{jobs: map[string]dbsim.RunJob{}} }

func (s *fakeStore) Create(_ context.Context, j dbsim.RunJob, a dbadmin.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failAudit {
		return errors.New("audit write failed")
	}
	for _, o := range s.jobs {
		if o.Status.Active() && (o.TargetID == j.TargetID || o.AgentID == j.AgentID) {
			return dbsim.ErrJobBusy
		}
	}
	s.jobs[j.ID] = j
	s.audits = append(s.audits, auditRow{a, j.ID})
	return nil
}
func (s *fakeStore) Get(_ context.Context, id string) (dbsim.RunJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return dbsim.RunJob{}, dbsim.ErrJobNotFound
	}
	return j, nil
}
func (s *fakeStore) Transition(_ context.Context, id string, from []dbsim.JobStatus, to dbsim.JobStatus, reason string, a dbadmin.AuditEntry) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return false, nil
	}
	hit := false
	for _, f := range from {
		hit = hit || f == j.Status
	}
	if !hit {
		return false, nil
	}
	if s.failAudit {
		return false, errors.New("audit write failed")
	}
	j.Status, j.Reason = to, reason
	s.jobs[id] = j
	s.audits = append(s.audits, auditRow{a, id})
	return true, nil
}
func (s *fakeStore) ActiveForTarget(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if j.Status.Active() && j.TargetID == id {
			return true, nil
		}
	}
	return false, nil
}
func (s *fakeStore) ActiveForAgent(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if j.Status.Active() && j.AgentID == id {
			return true, nil
		}
	}
	return false, nil
}
func (s *fakeStore) Expired(context.Context, time.Time) ([]dbsim.RunJob, error) { return nil, nil }
func (s *fakeStore) only(t *testing.T) dbsim.RunJob {
	t.Helper()
	if len(s.jobs) != 1 {
		t.Fatalf("jobs = %d, want 1", len(s.jobs))
	}
	for _, j := range s.jobs {
		return j
	}
	return dbsim.RunJob{}
}
func (s *fakeStore) actions() []string {
	var out []string
	for _, a := range s.audits {
		out = append(out, a.Entry.Action+":"+a.Entry.Outcome)
	}
	return out
}

type fakeDispatch struct {
	sent  bool
	calls []scenario.ScenarioCommand
	agent string
}

func (d *fakeDispatch) Dispatch(_ context.Context, agentID string, c scenario.ScenarioCommand) bool {
	d.calls = append(d.calls, c)
	d.agent = agentID
	return d.sent
}

type fakeCancel struct {
	sent bool
	runs []string
}

func (c *fakeCancel) Cancel(_ context.Context, _ string, runID string) bool {
	c.runs = append(c.runs, runID)
	return c.sent
}

type fakeActivity struct {
	busy bool
	err  error
}

func (a fakeActivity) HasRunningScenario(context.Context, string) (bool, error) { return a.busy, a.err }

// ---- fixtures ---------------------------------------------------------------

const scID = "dbsim-db03-unauthorized-access"

func sc() *scenario.Scenario {
	return &scenario.Scenario{ID: scID, Name: "Unauthorized access", ProductLine: "dbsim", Steps: []scenario.Step{{
		Name: "read restricted", TechniqueID: "T1078", Executor: "dbprobe", DBTarget: "ignored-yaml-name",
		DBProbe: "read_restricted_table", DBParams: map[string]string{"table": "restricted_t"},
	}}}
}

func rec(id string, mode dbsim.ExecMode) dbsim.TargetRecord {
	r := dbsim.TargetRecord{
		TargetRegistration: dbsim.TargetRegistration{
			ID: id, DisplayName: id, Engine: "postgresql", Host: "10.1.1.1", Port: 5432, Database: "app", TLSMode: "require",
			CredentialRef: "dbcred:" + id, AgentID: agentA, ExpectedIdentity: "7312345678901234567", Mode: mode,
			LabConfirmed: mode == dbsim.ModeLab,
		},
		CreatedBy: "u0", CreatedAt: t0.Add(-72 * time.Hour),
	}
	if mode == dbsim.ModeClient {
		r.IdentityCheck = dbsim.IdentityCheckState{Checked: true, Passed: true, At: t0.Add(-time.Hour), By: "u0"}
	}
	return r
}

type rig struct {
	svc   *Service
	store *fakeStore
	disp  *fakeDispatch
	canc  *fakeCancel
	tg    *fakeTargets
	gate  *bool
}

func newRig() *rig {
	on := true
	r := &rig{store: newStore(), disp: &fakeDispatch{sent: true}, canc: &fakeCancel{sent: true}, gate: &on}
	r.tg = &fakeTargets{recs: map[string]dbsim.TargetRecord{
		"lab-db":    rec("lab-db", dbsim.ModeLab),
		"client-db": rec("client-db", dbsim.ModeClient),
	}}
	r.svc = &Service{
		Targets: r.tg, Scenarios: fakeScenarios{scID: sc()}, Jobs: r.store, Dispatcher: r.disp, Canceller: r.canc,
		Activity: fakeActivity{}, Gate: dbsim.ClientGateFunc(func() bool { return *r.gate }),
		Now: func() time.Time { return t0 },
	}
	return r
}

var (
	admin   = dbadmin.Actor{ID: "u-admin", Role: auth.RoleAdmin, IP: "10.0.0.1"}
	analyst = dbadmin.Actor{ID: "u-analyst", Role: auth.RoleAnalyst, IP: "10.0.0.2"}
	viewer  = dbadmin.Actor{ID: "u-viewer", Role: auth.RoleViewer, IP: "10.0.0.3"}
)

func labReq() StartRequest {
	return StartRequest{TargetID: "lab-db", ScenarioIDs: []string{scID}, LabConfirmation: "lab-db"}
}
func clientReq() StartRequest {
	return StartRequest{TargetID: "client-db", ScenarioIDs: []string{scID}}
}

// ---- tests ------------------------------------------------------------------

func TestStartLabRunRequiresTypedTargetNameConfirmation(t *testing.T) {
	for _, conf := range []string{"", "LAB-DB", "lab-db ", "yes", "other-db"} {
		r := newRig()
		req := labReq()
		req.LabConfirmation = conf
		if _, err := r.svc.Start(context.Background(), analyst, req); !errors.Is(err, ErrConfirmationRequired) {
			t.Errorf("confirmation %q: err = %v, want ErrConfirmationRequired", conf, err)
		}
		if len(r.store.jobs) != 0 || len(r.disp.calls) != 0 {
			t.Errorf("confirmation %q: nothing may be stored or dispatched", conf)
		}
	}
	r := newRig()
	j, err := r.svc.Start(context.Background(), analyst, labReq())
	if err != nil {
		t.Fatal(err)
	}
	if j.LabConfirmation != "lab-db" || j.Mode != dbsim.ModeLab || j.CreatedBy != analyst.ID || j.Kind != dbsim.JobKindRun {
		t.Errorf("job = %+v", j)
	}
	if j.Status != dbsim.JobRunning {
		t.Errorf("status after successful dispatch = %s, want running", j.Status)
	}
	if got := r.store.only(t); got.Status != dbsim.JobRunning || got.LabConfirmation != "lab-db" {
		t.Errorf("stored = %+v", got)
	}
	if _, err := r.svc.Start(context.Background(), viewer, labReq()); !errors.Is(err, ErrNotPermitted) {
		t.Errorf("viewer: err = %v, want ErrNotPermitted", err)
	}
}

func TestStartClientRunRequiresAdminGateAndFreshIdentityCheck(t *testing.T) {
	r := newRig()
	if _, err := r.svc.Start(context.Background(), analyst, clientReq()); !errors.Is(err, ErrNotPermitted) {
		t.Errorf("analyst on client target: err = %v, want ErrNotPermitted", err)
	}
	*r.gate = false
	if _, err := r.svc.Start(context.Background(), admin, clientReq()); !errors.Is(err, ErrTargetNotReady) {
		t.Errorf("gate off: err = %v, want ErrTargetNotReady", err)
	}
	*r.gate = true
	stale := r.tg.recs["client-db"]
	stale.IdentityCheck.At = t0.Add(-48 * time.Hour)
	r.tg.recs["client-db"] = stale
	if _, err := r.svc.Start(context.Background(), admin, clientReq()); !errors.Is(err, ErrTargetNotReady) {
		t.Errorf("stale check: err = %v, want ErrTargetNotReady", err)
	}
	failed := r.tg.recs["client-db"]
	failed.IdentityCheck = dbsim.IdentityCheckState{Checked: true, Passed: false, At: t0.Add(-time.Minute)}
	r.tg.recs["client-db"] = failed
	if _, err := r.svc.Start(context.Background(), admin, clientReq()); !errors.Is(err, ErrTargetNotReady) {
		t.Errorf("failed check: err = %v, want ErrTargetNotReady", err)
	}
	if len(r.store.jobs) != 0 || len(r.disp.calls) != 0 {
		t.Fatal("no refused start may store or dispatch")
	}
	r2 := newRig()
	j, err := r2.svc.Start(context.Background(), admin, clientReq())
	if err != nil {
		t.Fatal(err)
	}
	if j.Mode != dbsim.ModeClient || j.LabConfirmation != "" {
		t.Errorf("job = %+v", j)
	}
}

func TestStartUsesTargetModeNeverRequestMode(t *testing.T) {
	// StartRequest has no mode field at all; the job mode is the target's.
	if _, ok := reflectField(StartRequest{}, "Mode"); ok {
		t.Fatal("StartRequest must not carry a mode")
	}
	r := newRig()
	j, err := r.svc.Start(context.Background(), analyst, labReq())
	if err != nil || j.Mode != dbsim.ModeLab {
		t.Fatalf("lab: %v %v", j.Mode, err)
	}
	for _, p := range j.Plan {
		if p.Spec.Mode != dbsim.ModeLab {
			t.Errorf("planned spec mode = %s", p.Spec.Mode)
		}
	}
	// A lab confirmation sent against a client target does not turn it into a lab run.
	r2 := newRig()
	req := clientReq()
	req.LabConfirmation = "client-db"
	if _, err := r2.svc.Start(context.Background(), analyst, req); !errors.Is(err, ErrNotPermitted) {
		t.Errorf("analyst + lab confirmation on a client target: err = %v, want ErrNotPermitted", err)
	}
}

func TestStartRefusesBusyTargetAndBusyAgent(t *testing.T) {
	r := newRig()
	if _, err := r.svc.Start(context.Background(), analyst, labReq()); err != nil {
		t.Fatal(err)
	}
	// Same target again.
	if _, err := r.svc.Start(context.Background(), analyst, labReq()); !errors.Is(err, ErrBusy) {
		t.Errorf("busy target: err = %v, want ErrBusy", err)
	}
	// Another target on the same agent.
	other := rec("lab-db2", dbsim.ModeLab)
	r.tg.recs["lab-db2"] = other
	req := StartRequest{TargetID: "lab-db2", ScenarioIDs: []string{scID}, LabConfirmation: "lab-db2"}
	if _, err := r.svc.Start(context.Background(), analyst, req); !errors.Is(err, ErrBusy) {
		t.Errorf("busy agent: err = %v, want ErrBusy", err)
	}
	if len(r.disp.calls) != 1 {
		t.Errorf("dispatches = %d, want 1", len(r.disp.calls))
	}
}

func TestStartRefusesWhenAgentRunsANormalScenarioFailClosed(t *testing.T) {
	for name, act := range map[string]AgentActivity{
		"running":   fakeActivity{busy: true},
		"error":     fakeActivity{err: errors.New("db down")},
		"not wired": nil,
	} {
		r := newRig()
		r.svc.Activity = act
		if _, err := r.svc.Start(context.Background(), analyst, labReq()); !errors.Is(err, ErrBusy) {
			t.Errorf("%s: err = %v, want ErrBusy", name, err)
		}
		if len(r.store.jobs) != 0 || len(r.disp.calls) != 0 {
			t.Errorf("%s: nothing may be stored or dispatched", name)
		}
	}
}

func TestStartStoreRaceIsBusy(t *testing.T) {
	// The in-memory view sees nothing active, but the store's unique index refuses.
	r := newRig()
	r.store.jobs["pre"] = dbsim.RunJob{ID: "pre", TargetID: "lab-db", AgentID: agentA, Status: dbsim.JobRunning}
	r.svc.Jobs = hideActive{r.store}
	if _, err := r.svc.Start(context.Background(), analyst, labReq()); !errors.Is(err, ErrBusy) {
		t.Errorf("err = %v, want ErrBusy from the store", err)
	}
	if len(r.disp.calls) != 0 {
		t.Error("must not dispatch")
	}
}

type hideActive struct{ *fakeStore }

func (hideActive) ActiveForTarget(context.Context, string) (bool, error) { return false, nil }
func (hideActive) ActiveForAgent(context.Context, string) (bool, error)  { return false, nil }

func TestStartMarksFailedWhenAgentOffline(t *testing.T) {
	r := newRig()
	r.disp.sent = false
	j, err := r.svc.Start(context.Background(), analyst, labReq())
	if !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("err = %v, want ErrAgentOffline", err)
	}
	got := r.store.only(t)
	if got.Status != dbsim.JobFailed || !strings.Contains(got.Reason, "offline") {
		t.Errorf("stored job = %s / %q", got.Status, got.Reason)
	}
	if j.ID != got.ID || j.Status != dbsim.JobFailed {
		t.Errorf("returned job = %+v", j)
	}
	acts := r.store.actions()
	if len(acts) != 2 || acts[0] != "dbsim.run_started:ok" || acts[1] != "dbsim.run_failed:error" {
		t.Errorf("audit rows = %v", acts)
	}
	// The failed job frees the target and agent.
	r.disp.sent = true
	if _, err := r.svc.Start(context.Background(), analyst, labReq()); err != nil {
		t.Errorf("restart after offline failure: %v", err)
	}
}

func TestStartStoresPlanWithMarkersAndNoSecrets(t *testing.T) {
	r := newRig()
	j, err := r.svc.Start(context.Background(), analyst, labReq())
	if err != nil {
		t.Fatal(err)
	}
	if len(j.Plan) != 1 || j.Plan[0].ScenarioID != scID || j.Plan[0].Index != 0 {
		t.Fatalf("plan = %+v", j.Plan)
	}
	sp := j.Plan[0].Spec
	if !strings.HasPrefix(sp.Marker, "bas-dbsim:") || sp.RunID != j.ID || sp.CredentialRef != "dbcred:lab-db" || sp.TargetID != "lab-db" {
		t.Errorf("spec = %+v", sp)
	}
	raw, _ := json.Marshal(j.Plan)
	low := strings.ToLower(string(raw))
	for _, bad := range []string{"password", "secret"} {
		if strings.Contains(low, bad) {
			t.Errorf("plan JSON contains %q: %s", bad, raw)
		}
	}
	if !strings.Contains(low, "dbcred:lab-db") {
		t.Error("plan must carry the credential reference")
	}
	// The command carries the same steps and run id, and the job deadline is budgeted per scenario.
	if len(r.disp.calls) != 1 || r.disp.calls[0].RunID != j.ID || len(r.disp.calls[0].Steps) != 1 || r.disp.agent != agentA {
		t.Errorf("dispatch = %+v agent %s", r.disp.calls, r.disp.agent)
	}
	if !j.Deadline.Equal(dbsim.DeadlineFor(t0, 1)) || !j.CreatedAt.Equal(t0) {
		t.Errorf("deadline/created = %v/%v", j.Deadline, j.CreatedAt)
	}
}

func TestStartValidatesScenarioSelection(t *testing.T) {
	r := newRig()
	r.svc.Scenarios = fakeScenarios{
		scID:                   sc(),
		"dbsim-no-expectation": {ID: "dbsim-no-expectation", ProductLine: "dbsim", Steps: sc().Steps},
		"other-line":           {ID: "other-line", ProductLine: "dlp", Steps: sc().Steps},
	}
	for name, ids := range map[string][]string{
		"empty": nil, "unknown": {"nope"}, "no expectation": {"dbsim-no-expectation"}, "other product line": {"other-line"},
		"duplicate": {scID, scID},
	} {
		req := labReq()
		req.ScenarioIDs = ids
		if _, err := r.svc.Start(context.Background(), analyst, req); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: err = %v, want ErrInvalidRequest", name, err)
		}
	}
	if len(r.store.jobs) != 0 {
		t.Error("nothing may be stored")
	}
	// An unknown target is not ready.
	req := labReq()
	req.TargetID = "nope"
	if _, err := r.svc.Start(context.Background(), analyst, req); !errors.Is(err, ErrTargetNotReady) {
		t.Errorf("unknown target: err = %v", err)
	}
}

func TestStartFailedAuditWriteStartsNothing(t *testing.T) {
	r := newRig()
	r.store.failAudit = true
	if _, err := r.svc.Start(context.Background(), analyst, labReq()); err == nil {
		t.Fatal("want error")
	}
	if len(r.disp.calls) != 0 {
		t.Error("must not dispatch when the job could not be recorded with its audit row")
	}
}

func TestStartIdentityCheck(t *testing.T) {
	r := newRig()
	if _, err := r.svc.StartIdentityCheck(context.Background(), analyst, "client-db"); !errors.Is(err, ErrNotPermitted) {
		t.Errorf("analyst: err = %v, want ErrNotPermitted", err)
	}
	// An unverified client target with the gate OFF can still be checked: that is how it earns the pass.
	*r.gate = false
	un := r.tg.recs["client-db"]
	un.IdentityCheck = dbsim.IdentityCheckState{}
	r.tg.recs["client-db"] = un
	j, err := r.svc.StartIdentityCheck(context.Background(), admin, "client-db")
	if err != nil {
		t.Fatal(err)
	}
	if j.Kind != dbsim.JobKindIdentityCheck || j.Status != dbsim.JobRunning || len(j.Plan) != 1 ||
		j.Plan[0].Spec.ProbeID != dbsim.ProbeCheckReadOnlyIdentity || j.Mode != dbsim.ModeClient {
		t.Errorf("job = %+v", j)
	}
	if len(r.disp.calls) != 1 || r.disp.calls[0].RunID != j.ID {
		t.Errorf("dispatch = %+v", r.disp.calls)
	}
	// One active job per target/agent applies.
	if _, err := r.svc.StartIdentityCheck(context.Background(), admin, "client-db"); !errors.Is(err, ErrBusy) {
		t.Errorf("second check: err = %v, want ErrBusy", err)
	}
	if _, err := r.svc.StartIdentityCheck(context.Background(), admin, "missing"); !errors.Is(err, ErrTargetNotReady) {
		t.Errorf("unknown target: err = %v", err)
	}
}

func TestCancelSendsCommandCancelAndMarksCancelled(t *testing.T) {
	r := newRig()
	j, err := r.svc.Start(context.Background(), analyst, labReq())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.svc.Cancel(context.Background(), analyst, j.ID); err != nil {
		t.Fatal(err)
	}
	if len(r.canc.runs) != 1 || r.canc.runs[0] != j.ID {
		t.Errorf("cancel commands = %v", r.canc.runs)
	}
	got, _ := r.store.Get(context.Background(), j.ID)
	if got.Status != dbsim.JobCancelled {
		t.Errorf("status = %s", got.Status)
	}
	acts := r.store.actions()
	if acts[len(acts)-1] != "dbsim.run_cancelled:ok" {
		t.Errorf("audit rows = %v", acts)
	}
	// A finished job cannot be cancelled again.
	if err := r.svc.Cancel(context.Background(), analyst, j.ID); !errors.Is(err, ErrNotActive) {
		t.Errorf("second cancel: err = %v, want ErrNotActive", err)
	}
	if err := r.svc.Cancel(context.Background(), analyst, "missing"); !errors.Is(err, dbsim.ErrJobNotFound) {
		t.Errorf("unknown job: err = %v", err)
	}
}

func TestCancelUnreachableAgentStillCancelsTheRecord(t *testing.T) {
	r := newRig()
	j, _ := r.svc.Start(context.Background(), analyst, labReq())
	r.canc.sent = false
	if err := r.svc.Cancel(context.Background(), analyst, j.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.store.Get(context.Background(), j.ID); got.Status != dbsim.JobCancelled {
		t.Errorf("status = %s", got.Status)
	}
}

func TestCancelRequiresRunPermission(t *testing.T) {
	r := newRig()
	j, _ := r.svc.Start(context.Background(), analyst, labReq())
	if err := r.svc.Cancel(context.Background(), viewer, j.ID); !errors.Is(err, ErrNotPermitted) {
		t.Errorf("viewer: err = %v, want ErrNotPermitted", err)
	}
	if len(r.canc.runs) != 0 {
		t.Error("a refused cancel must send nothing")
	}
	if got, _ := r.store.Get(context.Background(), j.ID); got.Status != dbsim.JobRunning {
		t.Errorf("status = %s, want still running", got.Status)
	}
}

func reflectField(v any, name string) (reflect.StructField, bool) {
	return reflect.TypeOf(v).FieldByName(name)
}
