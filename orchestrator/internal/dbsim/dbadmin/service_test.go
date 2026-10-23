package dbadmin

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/dbsim"
)

// ---- fakes ----------------------------------------------------------------
//
// The stores model the real ones: the state change and its audit row are one
// transaction, so a failing audit write leaves the state untouched.

type fakeAudit struct {
	entries []AuditEntry
	fail    bool // every audit write fails
}

func (f *fakeAudit) Log(e AuditEntry) error {
	if f.fail {
		return errors.New("audit store down")
	}
	f.entries = append(f.entries, e)
	return nil
}

func (f *fakeAudit) find(action, outcome string) *AuditEntry {
	for i := range f.entries {
		if f.entries[i].Action == action && f.entries[i].Outcome == outcome {
			return &f.entries[i]
		}
	}
	return nil
}

type fakeSettings struct {
	au       *fakeAudit
	val      string
	found    bool
	readErr  error
	writeErr error
	writes   int
	lastBy   string
}

func (f *fakeSettings) GetClientMode(ctx context.Context) (string, bool, error) {
	return f.val, f.found, f.readErr
}

func (f *fakeSettings) SetClientMode(ctx context.Context, enabled bool, by string, e AuditEntry) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	if err := f.au.Log(e); err != nil {
		return err
	}
	f.writes++
	f.lastBy = by
	f.found = true
	f.val = "false"
	if enabled {
		f.val = "true"
	}
	return nil
}

type fakeTargets struct {
	au        *fakeAudit
	recs      map[string]dbsim.TargetRecord
	saveCalls int
	createErr error
}

func newFakeTargets(au *fakeAudit) *fakeTargets {
	return &fakeTargets{au: au, recs: map[string]dbsim.TargetRecord{}}
}

func (f *fakeTargets) Create(ctx context.Context, r dbsim.TargetRecord, e AuditEntry) error {
	if f.createErr != nil {
		return f.createErr
	}
	if _, ok := f.recs[r.ID]; ok {
		return dbsim.ErrTargetExists
	}
	if err := f.au.Log(e); err != nil {
		return err
	}
	f.recs[r.ID] = r
	return nil
}

func (f *fakeTargets) Get(ctx context.Context, id string) (dbsim.TargetRecord, error) {
	r, ok := f.recs[id]
	if !ok {
		return dbsim.TargetRecord{}, dbsim.ErrTargetNotFound
	}
	return r, nil
}

func (f *fakeTargets) List(ctx context.Context) ([]dbsim.TargetRecord, error) {
	var out []dbsim.TargetRecord
	for _, r := range f.recs {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *fakeTargets) Delete(ctx context.Context, id string, e AuditEntry) error {
	if _, ok := f.recs[id]; !ok {
		return dbsim.ErrTargetNotFound
	}
	if err := f.au.Log(e); err != nil {
		return err
	}
	delete(f.recs, id)
	return nil
}

func (f *fakeTargets) SaveIdentityCheck(ctx context.Context, against dbsim.TargetRecord, st dbsim.IdentityCheckState, e AuditEntry) error {
	r, ok := f.recs[against.ID]
	if !ok {
		return dbsim.ErrTargetNotFound
	}
	if !r.SameConfig(against) {
		return dbsim.ErrTargetChanged
	}
	if err := f.au.Log(e); err != nil {
		return err
	}
	f.saveCalls++
	r.IdentityCheck = st
	f.recs[against.ID] = r
	return nil
}

type fakeRunner struct {
	res    dbsim.DBProbeResult
	err    error
	called int
	got    dbsim.Target
	onRun  func()
}

func (f *fakeRunner) RunIdentityCheck(ctx context.Context, t dbsim.Target) (dbsim.DBProbeResult, error) {
	f.called++
	f.got = t
	if f.onRun != nil {
		f.onRun()
	}
	return f.res, f.err
}

var (
	admin   = Actor{ID: "u-admin", Role: auth.RoleAdmin}
	analyst = Actor{ID: "u-analyst", Role: auth.RoleAnalyst}
	viewer  = Actor{ID: "u-viewer", Role: auth.RoleViewer}
	nobody  = Actor{ID: "u-x", Role: auth.Role("nobody")}
	t0      = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
)

func newSvc() (*Service, *fakeSettings, *fakeTargets, *fakeAudit) {
	au := &fakeAudit{}
	st, tg := &fakeSettings{au: au}, newFakeTargets(au)
	return &Service{Settings: st, Targets: tg, Audit: au, Now: func() time.Time { return t0 }}, st, tg, au
}

func pgReg() dbsim.TargetRegistration {
	return dbsim.TargetRegistration{ID: "prod-pg-1", Engine: "postgresql", Host: "db1.example.com", Port: 5432,
		CredentialRef: "dbcred:prod-pg-ro", ExpectedIdentity: "7312345678901234567", Mode: dbsim.ModeClient}
}

const clearNote = "identity_checks=can_write=no,can_ddl=no,can_admin=no,can_audit=no"

// ---- client mode setting ---------------------------------------------------

func TestEnableClientModeRequiresAdminAndWritesAudit(t *testing.T) {
	for _, a := range []Actor{analyst, viewer, nobody, {}} {
		s, st, _, au := newSvc()
		if err := s.SetClientMode(context.Background(), a, true); !errors.Is(err, ErrForbidden) {
			t.Fatalf("%+v: want ErrForbidden, got %v", a, err)
		}
		if st.writes != 0 || s.ClientModeEnabled() {
			t.Fatalf("%+v: a non-admin changed the setting", a)
		}
		if au.find("dbsim.client_mode_enabled", "ok") != nil {
			t.Fatalf("%+v: a refused change was audited as ok", a)
		}
	}

	s, st, _, au := newSvc()
	if s.ClientModeEnabled() {
		t.Fatal("default must be OFF")
	}
	if err := s.SetClientMode(context.Background(), admin, true); err != nil {
		t.Fatal(err)
	}
	if !s.ClientModeEnabled() || st.val != "true" || st.lastBy != "u-admin" {
		t.Fatalf("setting not stored: %+v", st)
	}
	e := au.find("dbsim.client_mode_enabled", "ok")
	if e == nil || e.ActorID != "u-admin" || e.Resource != "dbsim:client-mode" || e.Detail["enabled"] != true {
		t.Fatalf("enable not audited: %+v", au.entries)
	}
	if err := s.SetClientMode(context.Background(), admin, false); err != nil {
		t.Fatal(err)
	}
	if s.ClientModeEnabled() || au.find("dbsim.client_mode_disabled", "ok") == nil {
		t.Fatalf("disable not applied/audited: %+v", au.entries)
	}
}

func TestClientModeSettingFailsClosed(t *testing.T) {
	s, st, _, au := newSvc()
	st.val, st.found = "true", true
	st.readErr = errors.New("db down")
	if s.ClientModeEnabled() {
		t.Fatal("a settings read error must read as OFF")
	}
	// The gate handed to Authorize behaves the same.
	if s.Gate().ClientModeEnabled() {
		t.Fatal("gate must be OFF on a read error")
	}
	st.readErr = nil
	st.val = "TRUE"
	if s.ClientModeEnabled() {
		t.Fatal("only the exact stored value 'true' enables client mode")
	}
	// A write error leaves the setting off and is audited as an error.
	s2, st2, _, au2 := newSvc()
	st2.writeErr = errors.New("db down")
	if err := s2.SetClientMode(context.Background(), admin, true); err == nil {
		t.Fatal("write error swallowed")
	}
	if s2.ClientModeEnabled() || au2.find("dbsim.client_mode_enabled", "error") == nil {
		t.Fatalf("failed enable: enabled=%v audit=%+v", s2.ClientModeEnabled(), au2.entries)
	}
	_ = au
}

func TestNilServiceGateIsOff(t *testing.T) {
	var s *Service
	if s.ClientModeEnabled() {
		t.Fatal("nil service must be OFF")
	}
	if (&Service{}).ClientModeEnabled() {
		t.Fatal("service without a settings store must be OFF")
	}
}

// ---- registry --------------------------------------------------------------

func TestRegisterTargetStoresExpectedIdentity(t *testing.T) {
	s, _, tg, au := newSvc()
	rec, err := s.RegisterTarget(context.Background(), admin, pgReg())
	if err != nil {
		t.Fatal(err)
	}
	got := tg.recs["prod-pg-1"]
	if got.ExpectedIdentity != "7312345678901234567" || got.CredentialRef != "dbcred:prod-pg-ro" || got.CreatedBy != "u-admin" ||
		!got.CreatedAt.Equal(t0) || got.DBServerHost != "db1.example.com" || rec.ID != got.ID {
		t.Fatalf("stored record: %+v", got)
	}
	if got.IdentityCheck.Checked || got.ToTarget().ReadOnlyIdentityVerified {
		t.Fatal("a new target must not be verified")
	}
	e := au.find("dbsim.target_registered", "ok")
	if e == nil || e.Resource != "dbsim-target:prod-pg-1" || e.Detail["expectedIdentity"] != "7312345678901234567" || e.Detail["credentialRef"] != "dbcred:prod-pg-ro" {
		t.Fatalf("registration not audited with its identity: %+v", au.entries)
	}
	for k, v := range e.Detail {
		if strings.Contains(strings.ToLower(k), "password") || strings.Contains(strings.ToLower(k), "secret") {
			t.Errorf("audit detail has a secret-like key %q=%v", k, v)
		}
	}
}

func TestRegisterTargetRefusals(t *testing.T) {
	// Non-admin.
	for _, a := range []Actor{analyst, viewer, nobody} {
		s, _, tg, _ := newSvc()
		if _, err := s.RegisterTarget(context.Background(), a, pgReg()); !errors.Is(err, ErrForbidden) || len(tg.recs) != 0 {
			t.Fatalf("%+v: %v %v", a, err, tg.recs)
		}
	}
	// Invalid input never reaches the store and is not audited as ok.
	s, _, tg, au := newSvc()
	r := pgReg()
	r.ExpectedIdentity = ""
	if _, err := s.RegisterTarget(context.Background(), admin, r); !errors.Is(err, dbsim.ErrTargetInvalid) || len(tg.recs) != 0 {
		t.Fatalf("missing identity accepted: %v", err)
	}
	r = pgReg()
	r.CredentialRef = "hunter2-the-actual-password"
	_, err := s.RegisterTarget(context.Background(), admin, r)
	if !errors.Is(err, dbsim.ErrTargetInvalid) || len(tg.recs) != 0 || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("raw password accepted or echoed: %v", err)
	}
	for _, e := range au.entries {
		if e.Outcome == "ok" {
			t.Fatalf("an invalid registration was audited ok: %+v", e)
		}
		if strings.Contains(strings.Join(mapStrings(e.Detail), " "), "hunter2") {
			t.Fatalf("the rejected value was written to the audit log: %+v", e)
		}
	}
	// Duplicate id.
	if _, err := s.RegisterTarget(context.Background(), admin, pgReg()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterTarget(context.Background(), admin, pgReg()); !errors.Is(err, dbsim.ErrTargetExists) {
		t.Fatalf("duplicate: %v", err)
	}
	if au.find("dbsim.target_registered", "error") == nil {
		t.Fatal("a failed registration must be audited as an error")
	}
}

func mapStrings(m map[string]any) []string {
	var out []string
	for k, v := range m {
		out = append(out, k)
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func TestListGetDeleteTargets(t *testing.T) {
	s, _, tg, au := newSvc()
	if _, err := s.RegisterTarget(context.Background(), admin, pgReg()); err != nil {
		t.Fatal(err)
	}
	// Reading is Analyst+Admin; a viewer or unknown role cannot.
	for _, a := range []Actor{admin, analyst} {
		l, err := s.ListTargets(context.Background(), a)
		if err != nil || len(l) != 1 {
			t.Fatalf("%+v: %v %v", a, l, err)
		}
		if _, err := s.GetTarget(context.Background(), a, "prod-pg-1"); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []Actor{viewer, nobody} {
		if _, err := s.ListTargets(context.Background(), a); !errors.Is(err, ErrForbidden) {
			t.Fatalf("%+v list: %v", a, err)
		}
		if _, err := s.GetTarget(context.Background(), a, "prod-pg-1"); !errors.Is(err, ErrForbidden) {
			t.Fatalf("%+v get: %v", a, err)
		}
	}
	// Deleting is Admin only and audited.
	if err := s.DeleteTarget(context.Background(), analyst, "prod-pg-1"); !errors.Is(err, ErrForbidden) || len(tg.recs) != 1 {
		t.Fatalf("analyst delete: %v", err)
	}
	if err := s.DeleteTarget(context.Background(), admin, "prod-pg-1"); err != nil || len(tg.recs) != 0 {
		t.Fatalf("admin delete: %v", err)
	}
	if au.find("dbsim.target_deleted", "ok") == nil {
		t.Fatal("delete not audited")
	}
	if err := s.DeleteTarget(context.Background(), admin, "prod-pg-1"); !errors.Is(err, dbsim.ErrTargetNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
}

// ---- read-only identity check ----------------------------------------------

func registered(t *testing.T, r *fakeRunner) (*Service, *fakeTargets, *fakeAudit) {
	t.Helper()
	s, _, tg, au := newSvc()
	if r != nil {
		s.Runner = r
	}
	if _, err := s.RegisterTarget(context.Background(), admin, pgReg()); err != nil {
		t.Fatal(err)
	}
	return s, tg, au
}

func TestIdentityCheckPassRecordsWhoAndWhenAndVerifiesTheTarget(t *testing.T) {
	run := &fakeRunner{res: dbsim.DBProbeResult{Notes: []string{clearNote}}}
	s, tg, au := registered(t, run)
	res, rec, err := s.RunIdentityCheck(context.Background(), admin, "prod-pg-1")
	if err != nil || !res.Passed {
		t.Fatalf("%+v %v", res, err)
	}
	st := tg.recs["prod-pg-1"].IdentityCheck
	if !st.Checked || !st.Passed || st.By != "u-admin" || !st.At.Equal(t0) || !rec.ToTarget().ReadOnlyIdentityVerified {
		t.Fatalf("state %+v", st)
	}
	if !tg.recs["prod-pg-1"].ToTarget().ReadOnlyIdentityVerified {
		t.Fatal("a passed check must verify the stored target")
	}
	// The runner got exactly the stored target (identity from the registry, not from the request).
	if run.got.ExpectedIdentity != "7312345678901234567" || run.got.Mode != dbsim.ModeClient || run.got.CredentialRef != "dbcred:prod-pg-ro" {
		t.Fatalf("runner target %+v", run.got)
	}
	if e := au.find("dbsim.target_identity_checked", "ok"); e == nil || e.Detail["passed"] != true {
		t.Fatalf("check not audited: %+v", au.entries)
	}
}

func TestIdentityCheckFailureNeverVerifiesAndClearsAnEarlierPass(t *testing.T) {
	run := &fakeRunner{res: dbsim.DBProbeResult{Notes: []string{clearNote}}}
	s, tg, au := registered(t, run)
	if _, _, err := s.RunIdentityCheck(context.Background(), admin, "prod-pg-1"); err != nil {
		t.Fatal(err)
	}
	// The account has since been granted write: the next check fails and un-verifies the target.
	run.res = dbsim.DBProbeResult{Notes: []string{"identity_checks=can_write=yes,can_ddl=no,can_admin=no,can_audit=no"}}
	res, _, err := s.RunIdentityCheck(context.Background(), admin, "prod-pg-1")
	if err != nil || res.Passed || len(res.Reasons) == 0 {
		t.Fatalf("%+v %v", res, err)
	}
	st := tg.recs["prod-pg-1"].IdentityCheck
	if !st.Checked || st.Passed || len(st.Reasons) == 0 || tg.recs["prod-pg-1"].ToTarget().ReadOnlyIdentityVerified {
		t.Fatalf("a failed check left the target verified: %+v", st)
	}
	if e := au.find("dbsim.target_identity_checked", "ok"); e == nil {
		t.Fatalf("not audited: %+v", au.entries)
	}
	// Unobservable evidence also fails.
	run.res = dbsim.DBProbeResult{Notes: []string{"identity_checks=can_write=unknown,can_ddl=no,can_admin=no,can_audit=no"}, ErrorClass: "identity_check_incomplete"}
	if res, _, _ := s.RunIdentityCheck(context.Background(), admin, "prod-pg-1"); res.Passed {
		t.Fatal("unknown evidence passed")
	}
	// The runner failing (agent offline, credential missing...) records a failed check, never a pass.
	run.res, run.err = dbsim.DBProbeResult{}, errors.New("agent offline")
	if _, _, err := s.RunIdentityCheck(context.Background(), admin, "prod-pg-1"); err == nil {
		t.Fatal("runner error swallowed")
	}
	st = tg.recs["prod-pg-1"].IdentityCheck
	if st.Passed || tg.recs["prod-pg-1"].ToTarget().ReadOnlyIdentityVerified {
		t.Fatalf("runner failure left a pass: %+v", st)
	}
	if au.find("dbsim.target_identity_checked", "error") == nil {
		t.Fatal("runner failure not audited")
	}
}

func TestIdentityCheckUnavailableWithoutARunner(t *testing.T) {
	s, tg, au := registered(t, nil)
	_, _, err := s.RunIdentityCheck(context.Background(), admin, "prod-pg-1")
	if !errors.Is(err, ErrIdentityCheckUnavailable) {
		t.Fatalf("want ErrIdentityCheckUnavailable, got %v", err)
	}
	if tg.recs["prod-pg-1"].IdentityCheck.Checked || tg.saveCalls != 0 {
		t.Fatal("no runner must not record a check")
	}
	if au.find("dbsim.target_identity_checked", "error") == nil {
		t.Fatal("not audited")
	}
}

func TestIdentityCheckRefusals(t *testing.T) {
	run := &fakeRunner{res: dbsim.DBProbeResult{Notes: []string{clearNote}}}
	s, tg, _ := registered(t, run)
	for _, a := range []Actor{analyst, viewer, nobody} {
		if _, _, err := s.RunIdentityCheck(context.Background(), a, "prod-pg-1"); !errors.Is(err, ErrForbidden) {
			t.Fatalf("%+v: %v", a, err)
		}
	}
	if run.called != 0 || tg.saveCalls != 0 {
		t.Fatal("a refused caller reached the runner or the store")
	}
	if _, _, err := s.RunIdentityCheck(context.Background(), admin, "missing"); !errors.Is(err, dbsim.ErrTargetNotFound) {
		t.Fatalf("missing target: %v", err)
	}
	// A record the gate would not authorise (corrupted identity) never reaches the runner.
	r := tg.recs["prod-pg-1"]
	r.ExpectedIdentity = ""
	tg.recs["prod-pg-1"] = r
	if _, _, err := s.RunIdentityCheck(context.Background(), admin, "prod-pg-1"); err == nil || run.called != 0 {
		t.Fatalf("an unauthorised target reached the runner: %v called=%d", err, run.called)
	}
}
