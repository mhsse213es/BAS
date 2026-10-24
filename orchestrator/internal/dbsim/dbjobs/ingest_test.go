package dbjobs

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbadmin"
	"github.com/audspect/bas/internal/dbsim/dbrun"
	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/dlpreport"
	"github.com/audspect/bas/internal/scenario"
)

// ---- fakes ------------------------------------------------------------------

type fakeSink struct {
	mu      sync.Mutex
	rows    map[string]RunRecord
	order   []string
	saveErr error
	saves   int
}

func newSink() *fakeSink { return &fakeSink{rows: map[string]RunRecord{}} }

func (f *fakeSink) Save(_ context.Context, r RunRecord) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saves++
	if f.saveErr != nil {
		return false, f.saveErr
	}
	k := r.RunID + "/" + r.ScenarioID
	if _, ok := f.rows[k]; ok {
		return true, nil
	}
	f.rows[k] = r
	f.order = append(f.order, k)
	return false, nil
}
func (f *fakeSink) Count(_ context.Context, runID string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.rows {
		if r.RunID == runID {
			n++
		}
	}
	return n, nil
}
func (f *fakeSink) row(runID, scenarioID string) (RunRecord, bool) {
	r, ok := f.rows[runID+"/"+scenarioID]
	return r, ok
}

type ingestConn struct {
	calls int
	reply func(detectverify.VerifyRequest) (detectverify.VerifyResult, error)
}

func (c *ingestConn) Verify(_ context.Context, r detectverify.VerifyRequest) (detectverify.VerifyResult, error) {
	c.calls++
	if c.reply == nil {
		return detectverify.VerifyResult{Verdict: detectverify.VerdictNotDetected}, nil
	}
	return c.reply(r)
}
func (c *ingestConn) TestConnection(context.Context) error { return nil }

type fakeIdentityStore struct {
	rec     dbsim.TargetRecord
	getErr  error
	saveErr error
	saved   []dbsim.IdentityCheckState
	against []dbsim.TargetRecord
	audits  []dbadmin.AuditEntry
}

func (f *fakeIdentityStore) Get(context.Context, string) (dbsim.TargetRecord, error) {
	return f.rec, f.getErr
}
func (f *fakeIdentityStore) SaveIdentityCheck(_ context.Context, against dbsim.TargetRecord, st dbsim.IdentityCheckState, a dbadmin.AuditEntry) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saved = append(f.saved, st)
	f.against = append(f.against, against)
	f.audits = append(f.audits, a)
	f.rec.IdentityCheck = st
	return nil
}

// ---- fixtures ---------------------------------------------------------------

const (
	scDB01 = "dbsim-db01-auth-policy"
	scDB03 = "dbsim-db03-unauthorized-access"
	scDB05 = "dbsim-db05-suspicious-read"
)

type pstep struct{ sc, probe string }

var threeScenarios = []pstep{{scDB01, "auth_check"}, {scDB01, "read_roles"}, {scDB03, "read_restricted_table"}, {scDB05, "suspicious_read"}}

func dbsimScenario(id string) *scenario.Scenario {
	return &scenario.Scenario{ID: id, Name: id, ProductLine: scenario.ProductLineDBSim}
}

type ingestRig struct {
	svc   *Service
	store *fakeStore
	sink  *fakeSink
	tg    *fakeTargets
	conn  *ingestConn
	job   dbsim.RunJob
}

const runIDx = "bas-dbsim-run:0011223344556677"

func newIngestRig(t *testing.T, steps []pstep) *ingestRig {
	t.Helper()
	r := &ingestRig{store: newStore(), sink: newSink(), conn: &ingestConn{}}
	r.tg = &fakeTargets{recs: map[string]dbsim.TargetRecord{"lab-db": rec("lab-db", dbsim.ModeLab)}}
	r.svc = &Service{
		Targets: r.tg, Jobs: r.store, Sink: r.sink, Now: func() time.Time { return t0 },
		Scenarios:        fakeScenarios{scDB01: dbsimScenario(scDB01), scDB03: dbsimScenario(scDB03), scDB05: dbsimScenario(scDB05)},
		ConnectorFactory: func(context.Context) (detectverify.Connector, error) { return r.conn, nil },
	}
	var plan []dbsim.PlannedStep
	var ids []string
	seen := map[string]bool{}
	idx := map[string]int{}
	for i, s := range steps {
		if !seen[s.sc] {
			seen[s.sc] = true
			ids = append(ids, s.sc)
		}
		plan = append(plan, dbsim.PlannedStep{ScenarioID: s.sc, Index: idx[s.sc], TaskID: taskID(i), Spec: dbsim.DBProbeSpec{
			Engine: "postgresql", ProbeID: s.probe, TargetID: "lab-db", Host: "10.1.1.1", Port: 5432, Database: "app",
			CredentialRef: "dbcred:lab-db", RunID: runIDx, Marker: "bas-dbsim:marker" + taskID(i), Mode: dbsim.ModeLab,
		}})
		idx[s.sc]++
	}
	r.job = dbsim.RunJob{ID: runIDx, Kind: dbsim.JobKindRun, TargetID: "lab-db", AgentID: agentA, Mode: dbsim.ModeLab,
		ScenarioIDs: ids, Plan: plan, Status: dbsim.JobRunning, CreatedBy: "u1", CreatedAt: t0, Deadline: t0.Add(10 * time.Minute)}
	r.store.jobs[runIDx] = r.job
	return r
}

func taskID(i int) string { return "task-" + string(rune('a'+i)) }

// execFor is a plausible, completed agent answer for a step.
func execFor(p dbsim.PlannedStep) dbrun.AgentExec {
	pr := &dbsim.DBProbeResult{RowsRead: 1, DBTime: t0, AgentTime: t0, CleanupStatus: dbsim.CleanupNotApplicable}
	if p.Spec.ProbeID == "read_restricted_table" {
		pr.Denied, pr.RowsRead, pr.ErrorClass = true, 0, "permission_denied"
	}
	if p.Spec.ProbeID == "suspicious_read" {
		pr.CleanupStatus = dbsim.CleanupOK
	}
	return dbrun.AgentExec{TaskID: p.TaskID, DBProbe: pr}
}

func (r *ingestRig) results() []dbrun.AgentExec {
	var out []dbrun.AgentExec
	for _, p := range r.job.Plan {
		out = append(out, execFor(p))
	}
	return out
}

func (r *ingestRig) sub(results []dbrun.AgentExec) Submission {
	return Submission{RunID: runIDx, AgentID: agentA, Results: results}
}

func (r *ingestRig) status() dbsim.JobStatus { return r.store.jobs[runIDx].Status }

// ---- tests ------------------------------------------------------------------

func TestIngestUnknownRunIDIsNotHandled(t *testing.T) {
	r := newIngestRig(t, threeScenarios)
	for _, id := range []string{"some-normal-run", "", "bas-dbsim-run:ffffffffffffffff"} {
		handled, err := r.svc.Ingest(context.Background(), Submission{RunID: id, AgentID: agentA})
		if handled || err != nil {
			t.Errorf("run id %q: handled=%v err=%v, want false,nil", id, handled, err)
		}
	}
	if len(r.sink.rows) != 0 || r.status() != dbsim.JobRunning {
		t.Fatal("an unknown run id must touch nothing")
	}
}

func TestIngestGradesEachScenarioAndCompletesJob(t *testing.T) {
	r := newIngestRig(t, threeScenarios)
	handled, err := r.svc.Ingest(context.Background(), r.sub(r.results()))
	if !handled || err != nil {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if len(r.sink.rows) != 3 {
		t.Fatalf("rows = %d, want 3 (one per scenario, not per step)", len(r.sink.rows))
	}
	for _, sc := range []string{scDB01, scDB03, scDB05} {
		row, ok := r.sink.row(runIDx, sc)
		if !ok {
			t.Fatalf("no row for %s", sc)
		}
		if err := dbsim.ValidateStoredRun(row.ScenarioID, row.ScenarioVersion, row.TargetID, row.Engine, row.RunID, row.Result, row.Report); err != nil {
			t.Errorf("%s: row is not storable: %v", sc, err)
		}
		if row.TargetID != "lab-db" || row.Engine != "postgresql" {
			t.Errorf("%s: row = %+v", sc, row)
		}
	}
	if got := r.status(); got != dbsim.JobCompleted {
		t.Fatalf("status = %s, want completed", got)
	}
	last := r.store.audits[len(r.store.audits)-1].Entry
	if last.Action != "dbsim.run_completed" || last.Resource != "dbsim-run:"+runIDx {
		t.Errorf("audit = %+v", last)
	}
}

func TestIngestMultiStepScenarioTakesWorstVerdict(t *testing.T) {
	r := newIngestRig(t, []pstep{{scDB01, "auth_check"}, {scDB01, "read_roles"}})
	res := r.results()
	// The second step fails closed: the probe never ran.
	res[1] = dbrun.AgentExec{TaskID: res[1].TaskID, ExitCode: 1, Stderr: "boom"}
	if _, err := r.svc.Ingest(context.Background(), r.sub(res)); err != nil {
		t.Fatal(err)
	}
	row, ok := r.sink.row(runIDx, scDB01)
	if !ok || row.Result != string(dbsim.ResultError) {
		t.Fatalf("row = %+v ok=%v, want one ERROR row (worst verdict of the two steps)", row, ok)
	}
	if r.status() != dbsim.JobCompleted {
		t.Errorf("status = %s", r.status())
	}
}

func TestIngestPartialWhenAgentReportsPartialOrRowsMissing(t *testing.T) {
	t.Run("agent reports partial", func(t *testing.T) {
		r := newIngestRig(t, threeScenarios)
		s := r.sub(r.results())
		s.Partial = true
		if _, err := r.svc.Ingest(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		if r.status() != dbsim.JobPartial || len(r.sink.rows) != 3 {
			t.Fatalf("status=%s rows=%d, want partial with the 3 graded rows kept", r.status(), len(r.sink.rows))
		}
	})
	t.Run("results missing", func(t *testing.T) {
		r := newIngestRig(t, threeScenarios)
		res := r.results()[:3] // the db05 result never arrived
		if _, err := r.svc.Ingest(context.Background(), r.sub(res)); err != nil {
			t.Fatal(err)
		}
		if r.status() != dbsim.JobPartial || len(r.sink.rows) != 2 {
			t.Fatalf("status=%s rows=%d, want partial with 2 rows", r.status(), len(r.sink.rows))
		}
		if _, ok := r.sink.row(runIDx, scDB05); ok {
			t.Error("a scenario with no result must not get a row")
		}
	})
	t.Run("one step of a scenario missing", func(t *testing.T) {
		r := newIngestRig(t, threeScenarios)
		res := r.results()
		res = append(res[:1], res[2:]...) // db01's second step is gone: db01 is ungradable
		if _, err := r.svc.Ingest(context.Background(), r.sub(res)); err != nil {
			t.Fatal(err)
		}
		if _, ok := r.sink.row(runIDx, scDB01); ok {
			t.Error("a scenario with a missing step must not be graded from a subset")
		}
		if r.status() != dbsim.JobPartial {
			t.Errorf("status = %s, want partial", r.status())
		}
	})
	t.Run("nothing gradable is failed", func(t *testing.T) {
		r := newIngestRig(t, threeScenarios)
		if _, err := r.svc.Ingest(context.Background(), r.sub(nil)); err != nil {
			t.Fatal(err)
		}
		if r.status() != dbsim.JobFailed || len(r.sink.rows) != 0 {
			t.Fatalf("status=%s rows=%d, want failed with no rows", r.status(), len(r.sink.rows))
		}
	})
}

func TestIngestMatchesByEchoedTaskIDAndDropsUnknownEchoes(t *testing.T) {
	r := newIngestRig(t, threeScenarios)
	res := r.results()
	// Reversed order: the echoed task ids are authoritative.
	for i, j := 0, len(res)-1; i < j; i, j = i+1, j-1 {
		res[i], res[j] = res[j], res[i]
	}
	if _, err := r.svc.Ingest(context.Background(), r.sub(res)); err != nil {
		t.Fatal(err)
	}
	if r.status() != dbsim.JobCompleted || len(r.sink.rows) != 3 {
		t.Fatalf("status=%s rows=%d: results echoing their task id must match their plan step", r.status(), len(r.sink.rows))
	}

	r2 := newIngestRig(t, threeScenarios)
	res2 := r2.results()
	res2[3].TaskID = "task-not-in-plan"
	if _, err := r2.svc.Ingest(context.Background(), r2.sub(res2)); err != nil {
		t.Fatal(err)
	}
	if _, ok := r2.sink.row(runIDx, scDB05); ok || r2.status() != dbsim.JobPartial {
		t.Errorf("a result echoing a task id outside the plan must not be graded (status %s)", r2.status())
	}
}

func TestIngestDuplicateSubmissionIsIdempotent(t *testing.T) {
	r := newIngestRig(t, threeScenarios)
	if _, err := r.svc.Ingest(context.Background(), r.sub(r.results())); err != nil {
		t.Fatal(err)
	}
	auditsBefore, savesBefore := len(r.store.audits), r.sink.saves
	handled, err := r.svc.Ingest(context.Background(), r.sub(r.results()))
	if !handled || err != nil {
		t.Fatalf("replay: handled=%v err=%v, want true,nil", handled, err)
	}
	if len(r.sink.rows) != 3 || r.sink.saves != savesBefore || len(r.store.audits) != auditsBefore || r.status() != dbsim.JobCompleted {
		t.Errorf("a replay must change nothing: rows=%d saves=%d audits=%d status=%s", len(r.sink.rows), r.sink.saves-savesBefore, len(r.store.audits)-auditsBefore, r.status())
	}

	// A replay with MORE scenarios graded can never upgrade a partial job.
	p := newIngestRig(t, threeScenarios)
	if _, err := p.svc.Ingest(context.Background(), p.sub(p.results()[:3])); err != nil {
		t.Fatal(err)
	}
	if _, err := p.svc.Ingest(context.Background(), p.sub(p.results())); err != nil {
		t.Fatal(err)
	}
	if p.status() != dbsim.JobPartial || len(p.sink.rows) != 2 {
		t.Errorf("partial job after replay: status=%s rows=%d, want partial with 2 rows", p.status(), len(p.sink.rows))
	}
}

func TestIngestAlreadySavedRowOfAnActiveJobDoesNotDoubleSave(t *testing.T) {
	r := newIngestRig(t, threeScenarios)
	// An earlier delivery saved db03 and crashed before the transition.
	res := r.results()
	if _, err := r.svc.Ingest(context.Background(), r.sub(res)); err != nil {
		t.Fatal(err)
	}
	r.store.jobs[runIDx] = r.job // job back to running
	if _, err := r.svc.Ingest(context.Background(), r.sub(res)); err != nil {
		t.Fatal(err)
	}
	if len(r.sink.rows) != 3 || r.status() != dbsim.JobCompleted {
		t.Fatalf("rows=%d status=%s: duplicates count as saved, never as a second row", len(r.sink.rows), r.status())
	}
}

func TestIngestIgnoresResultForCancelledOrFailedJob(t *testing.T) {
	for _, st := range []dbsim.JobStatus{dbsim.JobCancelled, dbsim.JobFailed, dbsim.JobCompleted, dbsim.JobPartial} {
		r := newIngestRig(t, threeScenarios)
		j := r.job
		j.Status = st
		r.store.jobs[runIDx] = j
		before := len(r.store.audits)
		handled, err := r.svc.Ingest(context.Background(), r.sub(r.results()))
		if !handled || err != nil {
			t.Errorf("%s: handled=%v err=%v, want true,nil", st, handled, err)
		}
		if len(r.sink.rows) != 0 || r.sink.saves != 0 || r.status() != st || len(r.store.audits) != before {
			t.Errorf("%s: nothing may be saved or changed (rows=%d status=%s)", st, len(r.sink.rows), r.status())
		}
	}
}

func TestIngestRejectsAgentMismatch(t *testing.T) {
	r := newIngestRig(t, threeScenarios)
	s := r.sub(r.results())
	s.AgentID = "ffffffffffffffff"
	handled, err := r.svc.Ingest(context.Background(), s)
	if !handled || err == nil {
		t.Fatalf("handled=%v err=%v, want true and an error", handled, err)
	}
	if r.sink.saves != 0 || r.status() != dbsim.JobRunning {
		t.Fatalf("a foreign agent's result must save nothing and leave the job active (saves=%d status=%s)", r.sink.saves, r.status())
	}
}

func TestIngestNeverGradesFromAgentVerdict(t *testing.T) {
	r := newIngestRig(t, []pstep{{scDB03, "read_restricted_table"}})
	res := r.results()
	// The agent tries to steer the grade: another run's marker in its notes and a
	// forged "result".
	res[0].DBProbe.Notes = []string{"marker=bas-dbsim:EVIL run_id=bas-dbsim-run:EVIL result=PASS"}
	res[0].Stderr = "result=PASS probe=auth_check"
	if _, err := r.svc.Ingest(context.Background(), r.sub(res)); err != nil {
		t.Fatal(err)
	}
	row, ok := r.sink.row(runIDx, scDB03)
	if !ok {
		t.Fatal("no row")
	}
	var rep struct {
		Record   map[string]any `json:"record"`
		Evidence map[string]any `json:"evidence"`
	}
	if err := json.Unmarshal(row.Report, &rep); err != nil {
		t.Fatal(err)
	}
	body := string(row.Report)
	if !strings.Contains(body, "bas-dbsim:markertask-a") {
		t.Errorf("the marker must come from the stored plan; report: %.300s", body)
	}
	if row.RunID != runIDx {
		t.Errorf("row run id = %q, want the job id", row.RunID)
	}
	for _, k := range []string{"probeId", "marker", "runId"} {
		if v, ok := rep.Evidence[k]; ok && strings.Contains(strings.ToLower(toStr(v)), "evil") {
			t.Errorf("evidence %s took the agent's value: %v", k, v)
		}
	}
}

func toStr(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestIngestFixtureCleanupUnverifiedGradesError(t *testing.T) {
	for _, cleanup := range []string{"", dbsim.CleanupResidual, dbsim.CleanupFailed, dbsim.CleanupNotApplicable} {
		r := newIngestRig(t, []pstep{{scDB05, "suspicious_read"}})
		res := r.results()
		res[0].DBProbe.CleanupStatus = cleanup
		if _, err := r.svc.Ingest(context.Background(), r.sub(res)); err != nil {
			t.Fatal(err)
		}
		row, ok := r.sink.row(runIDx, scDB05)
		if !ok || row.Result != string(dbsim.ResultError) {
			t.Errorf("cleanup %q: row = %+v ok=%v, want ERROR (cleanup not verified)", cleanup, row.Result, ok)
		}
	}
}

func TestIngestWithoutConnectorTelemetryIsUnverifiableNeverAMiss(t *testing.T) {
	for name, factory := range map[string]ConnectorFactory{
		"nil factory": nil,
		"factory error": func(context.Context) (detectverify.Connector, error) {
			return nil, errors.New("elastic down password=hunter2")
		},
	} {
		r := newIngestRig(t, []pstep{{scDB05, "suspicious_read"}})
		r.svc.ConnectorFactory = factory
		if _, err := r.svc.Ingest(context.Background(), r.sub(r.results())); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		row, ok := r.sink.row(runIDx, scDB05)
		if !ok {
			t.Fatalf("%s: no row", name)
		}
		var rep dbsim.StoredReport
		if err := json.Unmarshal(row.Report, &rep); err != nil {
			t.Fatal(err)
		}
		if rep.Record.Telemetry != dlpreport.TelemetryUnverifiable {
			t.Errorf("%s: telemetry = %v, want Unverifiable", name, rep.Record.Telemetry)
		}
		if row.Result == string(dbsim.ResultPass) {
			t.Errorf("%s: a detection expectation must never pass without telemetry", name)
		}
		if strings.Contains(string(row.Report), "hunter2") {
			t.Errorf("%s: secret leaked into the report", name)
		}
	}
}

func TestIngestUsesConnectorFromFactory(t *testing.T) {
	r := newIngestRig(t, []pstep{{scDB05, "suspicious_read"}})
	if _, err := r.svc.Ingest(context.Background(), r.sub(r.results())); err != nil {
		t.Fatal(err)
	}
	if r.conn.calls == 0 {
		t.Error("the injected connector was never asked about the marker")
	}
}

func TestIngestErrorsAreRedacted(t *testing.T) {
	r := newIngestRig(t, threeScenarios)
	r.sink.saveErr = errors.New("insert failed: dial postgres://svc:hunter2@db:5432/x password=hunter2")
	handled, err := r.svc.Ingest(context.Background(), r.sub(r.results()))
	if !handled || err == nil {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error leaks a secret: %v", err)
	}
	// A storage failure leaves the job active: the replay or the reaper settles it.
	if r.status() != dbsim.JobRunning {
		t.Errorf("status = %s, want running after a storage failure", r.status())
	}
	for _, a := range r.store.audits {
		if strings.Contains(toStr(a.Entry.Detail), "hunter2") {
			t.Errorf("audit leaks a secret: %+v", a.Entry)
		}
	}

	m := newIngestRig(t, threeScenarios)
	s := m.sub(m.results())
	s.AgentID = "password=hunter2"
	if _, err := m.svc.Ingest(context.Background(), s); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("agent mismatch error = %v, want a redacted error", err)
	}
}

// ---- identity-check jobs ----------------------------------------------------

const clearIdentityNote = "identity_checks=can_write=no,can_ddl=no,can_admin=no,can_audit=no"

func newIdentityRig(t *testing.T) (*Service, *fakeStore, *fakeIdentityStore, dbsim.RunJob) {
	t.Helper()
	store := newStore()
	tr := rec("client-db", dbsim.ModeClient)
	ids := &fakeIdentityStore{rec: tr}
	job := dbsim.RunJob{ID: runIDx, Kind: dbsim.JobKindIdentityCheck, TargetID: "client-db", AgentID: agentA, Mode: dbsim.ModeClient,
		ScenarioIDs: []string{}, Status: dbsim.JobRunning, CreatedBy: "u-admin", CreatedAt: t0, Deadline: t0.Add(5 * time.Minute),
		Plan: []dbsim.PlannedStep{{Index: 0, TaskID: "task-id", Spec: dbsim.DBProbeSpec{
			Engine: tr.Engine, ProbeID: dbsim.ProbeCheckReadOnlyIdentity, TargetID: "client-db", Host: tr.Host, Port: tr.Port, Database: tr.Database,
			TLSMode: tr.TLSMode, ExpectedIdentity: tr.ExpectedIdentity, CredentialRef: tr.CredentialRef, RunID: runIDx, Marker: "m", Mode: dbsim.ModeClient}}}}
	store.jobs[runIDx] = job
	svc := &Service{Jobs: store, Now: func() time.Time { return t0 }, Identity: NewIdentityRecorder(ids)}
	return svc, store, ids, job
}

func idSub(notes ...string) Submission {
	return Submission{RunID: runIDx, AgentID: agentA, Results: []dbrun.AgentExec{{TaskID: "task-id",
		DBProbe: &dbsim.DBProbeResult{RowsRead: 1, DBTime: t0, AgentTime: t0, Notes: notes}}}}
}

func TestIngestIdentityCheckPassRecordsVersionBoundPass(t *testing.T) {
	svc, store, ids, job := newIdentityRig(t)
	handled, err := svc.Ingest(context.Background(), idSub(clearIdentityNote))
	if !handled || err != nil {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if len(ids.saved) != 1 || !ids.saved[0].Checked || !ids.saved[0].Passed || ids.saved[0].By != "u-admin" {
		t.Fatalf("saved = %+v, want one passed check by the job's creator", ids.saved)
	}
	if !ids.against[0].SameConfig(ids.rec) || ids.audits[0].Action != "dbsim.target_identity_checked" || ids.audits[0].Outcome != "ok" {
		t.Errorf("against/audit = %+v / %+v", ids.against[0], ids.audits[0])
	}
	if !ids.saved[0].At.Equal(job.CreatedAt) {
		t.Errorf("check time = %v, want the time the check started", ids.saved[0].At)
	}
	if store.jobs[runIDx].Status != dbsim.JobCompleted {
		t.Errorf("job status = %s, want completed", store.jobs[runIDx].Status)
	}
}

func TestIngestIdentityCheckMalformedResultRecordsFailure(t *testing.T) {
	cases := map[string]Submission{
		"garbage notes": idSub("identity_checks=nonsense"),
		"writer":        idSub("identity_checks=can_write=yes,can_ddl=no,can_admin=no,can_audit=no"),
		"no notes":      idSub(),
		"no result":     {RunID: runIDx, AgentID: agentA, Results: []dbrun.AgentExec{{TaskID: "task-id", ExitCode: 1, Stderr: "boom"}}},
		"no results":    {RunID: runIDx, AgentID: agentA},
		"partial":       {RunID: runIDx, AgentID: agentA, Partial: true, Results: idSub(clearIdentityNote).Results},
	}
	for name, sub := range cases {
		svc, store, ids, _ := newIdentityRig(t)
		// An earlier pass must be withdrawn.
		ids.rec.IdentityCheck = dbsim.IdentityCheckState{Checked: true, Passed: true, At: t0.Add(-time.Hour), By: "u0"}
		handled, err := svc.Ingest(context.Background(), sub)
		if !handled || err != nil {
			t.Fatalf("%s: handled=%v err=%v", name, handled, err)
		}
		if len(ids.saved) != 1 || !ids.saved[0].Checked || ids.saved[0].Passed {
			t.Errorf("%s: saved = %+v, want one FAILED check (never a pass)", name, ids.saved)
		}
		if ids.rec.IdentityCheck.Passed {
			t.Errorf("%s: the earlier pass was not withdrawn", name)
		}
		if st := store.jobs[runIDx].Status; !st.Terminal() || st == dbsim.JobCancelled {
			t.Errorf("%s: job status = %s", name, st)
		}
	}
}

func TestIngestIdentityCheckForChangedTargetRecordsNothing(t *testing.T) {
	mutate := map[string]func(*fakeIdentityStore){
		"re-registered after the check started": func(f *fakeIdentityStore) { f.rec.CreatedAt = t0.Add(time.Minute) },
		"host edited":                           func(f *fakeIdentityStore) { f.rec.Host = "10.9.9.9" },
		"identity edited":                       func(f *fakeIdentityStore) { f.rec.ExpectedIdentity = "other" },
		"rebound to another agent":              func(f *fakeIdentityStore) { f.rec.AgentID = "ffffffffffffffff" },
		"deleted":                               func(f *fakeIdentityStore) { f.getErr = dbsim.ErrTargetNotFound },
		"store says changed":                    func(f *fakeIdentityStore) { f.saveErr = dbsim.ErrTargetChanged },
		"store says superseded":                 func(f *fakeIdentityStore) { f.saveErr = dbsim.ErrIdentityCheckSuperseded },
	}
	for name, mut := range mutate {
		svc, _, ids, _ := newIdentityRig(t)
		mut(ids)
		before := ids.rec.IdentityCheck
		handled, err := svc.Ingest(context.Background(), idSub(clearIdentityNote))
		if !handled || err != nil {
			t.Errorf("%s: handled=%v err=%v, want true,nil", name, handled, err)
		}
		if len(ids.saved) != 0 || ids.rec.IdentityCheck.Passed != before.Passed || ids.rec.IdentityCheck.Checked != before.Checked {
			t.Errorf("%s: nothing may be recorded, saved=%+v", name, ids.saved)
		}
	}
}

func TestIngestIdentityCheckWithoutRecorderRecordsNothing(t *testing.T) {
	svc, store, ids, _ := newIdentityRig(t)
	svc.Identity = nil
	handled, err := svc.Ingest(context.Background(), idSub(clearIdentityNote))
	if !handled || err == nil {
		t.Fatalf("handled=%v err=%v, want true and an error", handled, err)
	}
	if len(ids.saved) != 0 || store.jobs[runIDx].Status != dbsim.JobFailed {
		t.Errorf("saved=%+v status=%s, want nothing recorded and the job failed", ids.saved, store.jobs[runIDx].Status)
	}
}

func TestIngestIdentityCheckRecorderErrorIsRedacted(t *testing.T) {
	svc, _, ids, _ := newIdentityRig(t)
	ids.saveErr = errors.New("tx failed password=hunter2")
	_, err := svc.Ingest(context.Background(), idSub(clearIdentityNote))
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("err = %v, want a redacted error", err)
	}
}
