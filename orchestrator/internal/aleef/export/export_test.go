package export

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/audspect/bas/internal/aleef/exec"
	"github.com/audspect/bas/internal/aleef/generate"
	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/property"
	"github.com/audspect/bas/internal/aleef/safety"
	"github.com/audspect/bas/internal/aleef/store"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/runner"
)

// ---- a small toy application, written for the export tests ----
//
// Routes: GET/DELETE /api/v2/items/{id}, POST /api/v2/items/{id}/archive.
// Switches: readFlaw (another customer's item can be read), roleFlaw
// (non-admins can archive), adminNoArchive (the legitimate archive is refused),
// delFails (compensation fails).

type titem struct{ ID, Owner, Title, Status string }

type toy struct {
	mu             sync.Mutex
	items          map[string]*titem
	readFlaw       bool
	roleFlaw       bool
	adminNoArchive bool
	delFails       bool
	tokens         map[string][2]string
}

func newToy() *toy {
	t := &toy{tokens: map[string][2]string{
		"tok-alice": {"cust-a", "member"}, "tok-bob": {"cust-b", "member"}, "tok-dave": {"cust-d", "admin"},
	}}
	t.reset()
	return t
}

func (t *toy) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.items = map[string]*titem{}
	for _, s := range []struct{ id, owner, who string }{{"item-a1", "cust-a", "alice"}, {"item-b1", "cust-b", "bob"}, {"item-d1", "cust-d", "dave"}} {
		t.items[s.id] = &titem{ID: s.id, Owner: s.owner, Title: "ALEEF-CANARY-t-" + s.who, Status: "pending"}
	}
}

func (t *toy) Snapshot(context.Context) (map[string]runner.StateRecord, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[string]runner.StateRecord{}
	for id, it := range t.items {
		out[id] = runner.StateRecord{ID: id, OwnerID: it.Owner, Status: it.Status, Tag: it.Title}
	}
	return out, nil
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (t *toy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	who, ok := t.tokens[tok]
	if !ok {
		reply(w, 401, map[string]any{"error": "unauthenticated"})
		return
	}
	cust, role := who[0], who[1]
	p := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(p) < 4 || p[0] != "api" || p[2] != "items" {
		reply(w, 404, map[string]any{"error": "no route"})
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	it, found := t.items[p[3]]
	if !found {
		reply(w, 404, map[string]any{"error": "not found"})
		return
	}
	switch {
	case len(p) == 4 && r.Method == "GET":
		if it.Owner != cust && !t.readFlaw {
			reply(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		reply(w, 200, map[string]any{"id": it.ID, "owner": it.Owner, "title": it.Title, "status": it.Status})
	case len(p) == 4 && r.Method == "DELETE":
		if t.delFails {
			reply(w, 500, map[string]any{"error": "boom"})
			return
		}
		delete(t.items, it.ID)
		reply(w, 200, map[string]any{"ok": true})
	case len(p) == 5 && p[4] == "archive" && r.Method == "POST":
		if it.Owner != cust || (role != "admin" && !t.roleFlaw) || (role == "admin" && t.adminNoArchive) {
			reply(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		it.Status = "archived"
		reply(w, 200, map[string]any{"ok": true})
	default:
		reply(w, 404, map[string]any{"error": "no route"})
	}
}

type secretMap map[string]string

func (s secretMap) Resolve(ref string) (string, error) {
	if v, ok := s[ref]; ok {
		return v, nil
	}
	return "", fmt.Errorf("no secret")
}

func toyAccounts() []model.Account {
	return []model.Account{
		{Name: "alice", CustomerID: "cust-a", TokenRef: "tok-alice", Role: "member"},
		{Name: "bob", CustomerID: "cust-b", TokenRef: "tok-bob", Role: "member"},
		{Name: "dave", CustomerID: "cust-d", TokenRef: "tok-dave", Role: "admin"},
	}
}

func toyFixture() fixture.Fixture {
	f := fixture.Fixture{Name: "toy"}
	objs := map[string]string{"alice": "item-a1", "bob": "item-b1", "dave": "item-d1"}
	for _, a := range toyAccounts() {
		f.Identities = append(f.Identities, fixture.Identity{Name: a.Name, CustomerID: a.CustomerID, TokenRef: a.TokenRef, Role: a.Role})
		f.Objects = append(f.Objects, fixture.Object{
			ID: objs[a.Name], OwnerID: a.CustomerID, Status: "pending",
			Public: map[string]string{}, Protected: map[string]string{"canary": "ALEEF-CANARY-t-" + a.Name},
		})
	}
	return f
}

func toyModel() model.Model {
	idp := []model.Param{{Name: "id", In: "path", IsObjectID: true, Required: true, Schema: &model.Schema{Type: "string"}}}
	str := &model.Schema{Type: "string"}
	return model.Model{
		Roles: []string{"member", "admin"},
		Operations: []model.Operation{
			{ID: "getV2", Method: "GET", Path: "/api/v2/items/{id}", PathParams: idp, Class: model.ClassRead},
			{ID: "deleteV2", Method: "DELETE", Path: "/api/v2/items/{id}", PathParams: idp, Class: model.ClassReversible},
			{ID: "archive", Method: "POST", Path: "/api/v2/items/{id}/archive", PathParams: idp, Class: model.ClassReversible,
				Body: &model.Schema{Type: "object", Properties: map[string]*model.Schema{"reason": str}}},
		},
	}
}

func toyCreated() []model.CreatedObject {
	return []model.CreatedObject{
		{Operation: "seed", ID: "item-a1", Owner: "cust-a", Compensate: "deleteV2"},
		{Operation: "seed", ID: "item-b1", Owner: "cust-b", Compensate: "deleteV2"},
	}
}

func generatedFor(t *testing.T, prop, opID string) generate.Test {
	t.Helper()
	tests, err := generate.Generate(toyModel(), toyFixture(), toyAccounts(), generate.Options{
		Seed: 1, Catalogue: []contract.Scenario{},
		ReservedRoles: map[string]string{"archive": "admin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range tests {
		if x.Property == prop && x.Params["operation"] == opID {
			if x.OwnerControl == nil || x.NegativeControl == nil || x.ControlsBlocked {
				t.Fatalf("%s/%s has no controls", prop, opID)
			}
			return x
		}
	}
	t.Fatalf("no generated test %s on %s", prop, opID)
	return generate.Test{}
}

// fakeEnv implements verify.Env over the toy.
type fakeEnv struct {
	ty     *toy
	srv    *httptest.Server
	fresh  int
	clean  int
	orphan *model.CreatedObject
}

func newEnv(t *testing.T, ty *toy) *fakeEnv {
	srv := httptest.NewServer(ty)
	t.Cleanup(srv.Close)
	return &fakeEnv{ty: ty, srv: srv}
}

func (e *fakeEnv) Fresh(ctx context.Context) (*exec.Executor, func(context.Context) ([]model.CreatedObject, error), error) {
	e.fresh++
	e.ty.reset()
	now := time.Now()
	g, err := safety.NewGuard(safety.Engagement{ID: "toy", Customer: "toy", Environment: "lab", Hosts: []string{e.srv.URL}, Approver: "test",
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), MaxRequests: 1 << 20, MaxConcurrent: 64, RPS: 1e6,
	}, nil, toyModel(), safety.GuardOptions{})
	if err != nil {
		return nil, nil, err
	}
	ex, err := exec.New(exec.Config{
		Guard: g, BaseURL: e.srv.URL, Fixture: toyFixture(), Model: toyModel(), Created: toyCreated(), StateExtra: e.ty,
		Secrets: secretMap{"tok-alice": "tok-alice", "tok-bob": "tok-bob", "tok-dave": "tok-dave"},
	})
	if err != nil {
		return nil, nil, err
	}
	cleanup := func(ctx context.Context) ([]model.CreatedObject, error) {
		e.clean++
		if e.orphan != nil {
			return []model.CreatedObject{*e.orphan}, fmt.Errorf("%w: 1 object(s) not compensated", exec.ErrCleanupFailed)
		}
		err := ex.Cleanup(ctx)
		return ex.Orphans(), err
	}
	return ex, cleanup, nil
}

// ---- helpers ----

func verifiedFinding(t generate.Test) store.Finding {
	return store.Finding{ID: "f-1", RunID: "r1", TestID: t.ID, Property: t.Property, State: store.StateVerified, EvidenceHash: "abc123"}
}

func mustReg(t *testing.T, x generate.Test, seq int) Regression {
	t.Helper()
	r, err := ToRegression(verifiedFinding(x), x, seq)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func ownTest(t *testing.T) generate.Test  { return generatedFor(t, "P-OWN-1", "getV2") }
func roleTest(t *testing.T) generate.Test { return generatedFor(t, "P-ROLE-1", "archive") }

// ---- ToRegression ----

func TestToRegressionRefusesNonVerifiedFinding(t *testing.T) {
	x := ownTest(t)
	good := verifiedFinding(x)
	for _, st := range []string{store.StateCandidate, store.StateRejected, store.StateUnconfirmed, ""} {
		f := good
		f.State = st
		if _, err := ToRegression(f, x, 1); err == nil {
			t.Errorf("state %q: want refusal", st)
		}
	}
	f := good
	f.EvidenceHash = ""
	if _, err := ToRegression(f, x, 1); err == nil {
		t.Error("empty evidence hash: want refusal")
	}
	f = good
	f.TestID = "ALEEF-GEN-P-OWN-1-deadbeef"
	if _, err := ToRegression(f, x, 1); err == nil {
		t.Error("mismatched test id: want refusal")
	}
	blocked := x
	blocked.ControlsBlocked = true
	if _, err := ToRegression(good, blocked, 1); err == nil {
		t.Error("controls blocked: want refusal")
	}
	noOC := x
	noOC.OwnerControl = nil
	if _, err := ToRegression(good, noOC, 1); err == nil {
		t.Error("missing owner control: want refusal")
	}
	noNC := x
	noNC.NegativeControl = nil
	if _, err := ToRegression(good, noNC, 1); err == nil {
		t.Error("missing negative control: want refusal")
	}
	for _, seq := range []int{0, -1, 10000} {
		if _, err := ToRegression(good, x, seq); err == nil {
			t.Errorf("seq %d: want refusal", seq)
		}
	}
	if _, err := ToRegression(good, x, 9999); err != nil {
		t.Errorf("seq 9999: %v", err)
	}
	// the input test is not modified
	if x.Scenario.ID == "ALEEF-REG-0001" || x.OwnerControl.ID != x.ID+"-OC" {
		t.Error("input test was mutated")
	}
}

func TestExportedScenarioValidates(t *testing.T) {
	for _, x := range []generate.Test{ownTest(t), roleTest(t)} {
		r := mustReg(t, x, 1)
		b := r.Bundle
		if b.RegressionID != "ALEEF-REG-0001" || b.FindingID != "f-1" || b.EvidenceHash != "abc123" || b.Property != x.Property || b.Version != BundleVersion {
			t.Fatalf("bundle header %+v", b)
		}
		tt := b.Test
		if tt.ID != "ALEEF-REG-0001" || tt.Scenario.ID != "ALEEF-REG-0001" || tt.Scenario.Category != "ALEEF" {
			t.Fatalf("test ids %s / %s", tt.ID, tt.Scenario.ID)
		}
		if tt.OwnerControl == nil || tt.NegativeControl == nil || tt.ControlsBlocked {
			t.Fatal("controls missing")
		}
		if tt.OwnerControl.ID != "ALEEF-REG-0001-OC" || tt.OwnerControl.Scenario.ID != "ALEEF-REG-0001-OC" ||
			tt.NegativeControl.ID != "ALEEF-REG-0001-NC" || tt.NegativeControl.Scenario.ID != "ALEEF-REG-0001-NC" {
			t.Fatalf("control ids %s %s", tt.OwnerControl.Scenario.ID, tt.NegativeControl.Scenario.ID)
		}
		for _, s := range []contract.Scenario{tt.Scenario, tt.OwnerControl.Scenario, tt.NegativeControl.Scenario} {
			if err := s.Validate(); err != nil {
				t.Errorf("%s: %v", s.ID, err)
			}
		}
		if !reflect.DeepEqual(tt.Scenario.Steps, x.Scenario.Steps) {
			t.Error("steps changed")
		}
		if len(r.BundleJSON) == 0 {
			t.Error("no bundle json")
		}
	}
	if r := mustReg(t, ownTest(t), 42); r.Bundle.RegressionID != "ALEEF-REG-0042" {
		t.Errorf("seq 42 -> %s", r.Bundle.RegressionID)
	}
}

func TestYAMLOnlyForRunnerGradeOracle(t *testing.T) {
	// runner-grade, cross-identity.
	x := ownTest(t)
	if x.Template.Oracle != property.OracleRunnerGrade || !x.Template.RunnerLeakValid || !x.Template.RunnerStateValid {
		t.Fatalf("P-OWN-1 template is not runner-grade authoritative: %+v", x.Template.Oracle)
	}
	r := mustReg(t, x, 7)
	if r.ScenarioYAML == nil || r.YAMLNote != "" {
		t.Fatalf("yaml %v note %q", r.ScenarioYAML != nil, r.YAMLNote)
	}
	s, err := contract.Parse(r.ScenarioYAML)
	if err != nil {
		t.Fatalf("contract.Parse: %v\n%s", err, r.ScenarioYAML)
	}
	if s.ID != "ALEEF-REG-0007" || len(s.NegativeTests) == 0 || !strings.Contains(strings.ToUpper(s.NegativeTests[0]), "PASS") {
		t.Fatalf("negative tests %v", s.NegativeTests)
	}
	bs := r.Bundle.Test.Scenario
	if !reflect.DeepEqual(s.DeniedStatuses, bs.DeniedStatuses) || s.Claim != bs.Claim || len(s.Steps) != len(bs.Steps) ||
		s.SideEffectClass != bs.SideEffectClass || s.ExpectedControl != bs.ExpectedControl {
		t.Fatal("yaml differs from the bundle scenario")
	}
	for i := range s.Steps {
		if s.Steps[i].ID != bs.Steps[i].ID || s.Steps[i].Method != bs.Steps[i].Method || s.Steps[i].Path != bs.Steps[i].Path ||
			s.Steps[i].Identity != bs.Steps[i].Identity || s.Steps[i].Role != bs.Steps[i].Role {
			t.Fatalf("step %d differs", i)
		}
	}
	if len(s.IndustryMapping) != 0 || len(s.RegulatoryMapping) != 0 {
		t.Error("mappings must be empty")
	}
	for _, want := range []string{"f-1", "abc123"} {
		head := string(r.ScenarioYAML[:bytes.IndexByte(r.ScenarioYAML, '\n')+1])
		if !strings.HasPrefix(head, "#") || !strings.Contains(string(r.ScenarioYAML[:200]), want) {
			t.Errorf("header comment lacks %q:\n%s", want, r.ScenarioYAML[:200])
		}
	}

	// a runner-grade state-changing template must carry cleanup in the yaml.
	var sc *generate.Test
	tests, err := generate.Generate(toyModel(), toyFixture(), toyAccounts(), generate.Options{Seed: 1, Catalogue: []contract.Scenario{}, ReservedRoles: map[string]string{"archive": "admin"}})
	if err != nil {
		t.Fatal(err)
	}
	for i, g := range tests {
		if g.Template.Oracle == property.OracleRunnerGrade && g.Template.RunnerLeakValid && g.Template.RunnerStateValid &&
			g.Scenario.SideEffectClass == "STATE_CHANGE_SANDBOX" && !g.ControlsBlocked {
			sc = &tests[i]
			break
		}
	}
	if sc != nil {
		rr := mustReg(t, *sc, 2)
		ps, err := contract.Parse(rr.ScenarioYAML)
		if err != nil || len(ps.Cleanup) == 0 {
			t.Fatalf("state-change yaml: %v cleanup %v", err, ps.Cleanup)
		}
	}

	// a state-change oracle (P-ROLE-1 write) gets no yaml, but a note.
	y := roleTest(t)
	if y.Template.Oracle == property.OracleRunnerGrade {
		t.Fatalf("expected a non-runner-grade oracle for P-ROLE-1, got %s", y.Template.Oracle)
	}
	ry := mustReg(t, y, 3)
	if ry.ScenarioYAML != nil || ry.YAMLNote == "" || !strings.Contains(ry.YAMLNote, "exec") {
		t.Fatalf("yaml %q note %q", ry.ScenarioYAML, ry.YAMLNote)
	}
	if len(ry.BundleJSON) == 0 {
		t.Fatal("bundle must still be produced")
	}
}

// ---- bundle ----

func TestBundleRoundTrip(t *testing.T) {
	for _, x := range []generate.Test{ownTest(t), roleTest(t)} {
		b := mustReg(t, x, 1).Bundle
		raw, err := MarshalBundle(b)
		if err != nil {
			t.Fatal(err)
		}
		got, err := UnmarshalBundle(raw)
		if err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !reflect.DeepEqual(b, got) {
			t.Fatalf("round trip differs for %s", x.Property)
		}
		again, err := MarshalBundle(got)
		if err != nil || !bytes.Equal(raw, again) {
			t.Fatal("re-marshal differs")
		}
	}
	b := mustReg(t, ownTest(t), 1).Bundle
	b.Version = 99
	raw, _ := MarshalBundle(b)
	if _, err := UnmarshalBundle(raw); err == nil {
		t.Fatal("wrong version accepted")
	}
	raw, _ = MarshalBundle(mustReg(t, ownTest(t), 1).Bundle)
	bad := bytes.Replace(raw, []byte(`"Claim": "cross_identity"`), []byte(`"Claim": "bogus"`), 1)
	if bytes.Equal(bad, raw) {
		t.Fatal("tamper did not apply")
	}
	if _, err := UnmarshalBundle(bad); err == nil {
		t.Fatal("tampered scenario accepted")
	}
	b = mustReg(t, ownTest(t), 1).Bundle
	b.Test.OwnerControl = nil
	raw, _ = MarshalBundle(b)
	if _, err := UnmarshalBundle(raw); err == nil {
		t.Fatal("bundle without controls accepted")
	}
	if _, err := UnmarshalBundle([]byte(`{`)); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestBundleDeterministic(t *testing.T) {
	a := mustReg(t, roleTest(t), 5)
	b := mustReg(t, roleTest(t), 5)
	if !bytes.Equal(a.BundleJSON, b.BundleJSON) || !bytes.Equal(a.ScenarioYAML, b.ScenarioYAML) || a.YAMLNote != b.YAMLNote {
		t.Fatal("export is not deterministic")
	}
	c := mustReg(t, ownTest(t), 5)
	d := mustReg(t, ownTest(t), 5)
	if !bytes.Equal(c.BundleJSON, d.BundleJSON) || !bytes.Equal(c.ScenarioYAML, d.ScenarioYAML) {
		t.Fatal("export is not deterministic")
	}
	if tsPattern.Match(a.BundleJSON) || tsPattern.Match(c.BundleJSON) {
		t.Fatal("bundle carries a timestamp")
	}
}

var tsPattern = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}`)

// ---- Check ----

func check(t *testing.T, env *fakeEnv, x generate.Test) (Outcome, error) {
	t.Helper()
	b := mustReg(t, x, 1).Bundle
	return Check(context.Background(), env, b)
}

func TestCheckConfirmsFixOnCorrectedToy(t *testing.T) {
	for _, x := range []generate.Test{ownTest(t), roleTest(t)} {
		env := newEnv(t, newToy()) // no flaw: the corrected application
		out, err := check(t, env, x)
		if err != nil || out != FixedConfirmed {
			t.Fatalf("%s: %v %v", x.Property, out, err)
		}
		if env.fresh != 2 || env.clean != 2 {
			t.Fatalf("fresh %d cleaned %d, want 2 each", env.fresh, env.clean)
		}
	}
}

func TestCheckStillVulnerableOnFlawedToy(t *testing.T) {
	ty := newToy()
	ty.readFlaw = true
	out, err := check(t, newEnv(t, ty), ownTest(t))
	if err != nil || out != StillVulnerable {
		t.Fatalf("own: %v %v", out, err)
	}
	ty = newToy()
	ty.roleFlaw = true
	out, err = check(t, newEnv(t, ty), roleTest(t))
	if err != nil || out != StillVulnerable {
		t.Fatalf("role: %v %v", out, err)
	}
}

func TestCheckInconclusiveWhenOwnerControlFails(t *testing.T) {
	ty := newToy()
	ty.adminNoArchive = true // the legitimate actor is refused: the environment is not sound
	env := newEnv(t, ty)
	out, err := check(t, env, roleTest(t))
	if out != Inconclusive {
		t.Fatalf("want inconclusive, got %v (%v)", out, err)
	}
	if env.fresh != 2 {
		t.Fatalf("fresh %d", env.fresh)
	}
}

func TestCheckInconclusiveOnCleanupFailure(t *testing.T) {
	orphan := model.CreatedObject{Operation: "seed", ID: "item-a1", Owner: "cust-a", Compensate: "deleteV2"}
	env := newEnv(t, newToy())
	env.orphan = &orphan
	out, err := check(t, env, ownTest(t))
	if out != Inconclusive || err == nil || !errors.Is(err, exec.ErrCleanupFailed) {
		t.Fatalf("want inconclusive with cleanup error, got %v %v", out, err)
	}
	if strings.Contains(err.Error(), "ALEEF-CANARY") || strings.Contains(err.Error(), "tok-") {
		t.Fatalf("error leaks data: %v", err)
	}
	// a real compensation failure is the same.
	ty := newToy()
	ty.delFails = true
	out, err = check(t, newEnv(t, ty), ownTest(t))
	if out != Inconclusive || err == nil {
		t.Fatalf("real failure: %v %v", out, err)
	}
}

func TestCheckRefusesInvalidBundleAndCancelledContext(t *testing.T) {
	b := mustReg(t, ownTest(t), 1).Bundle
	b.Test.OwnerControl = nil
	if out, err := Check(context.Background(), newEnv(t, newToy()), b); out != Inconclusive || err == nil {
		t.Fatalf("%v %v", out, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b = mustReg(t, ownTest(t), 1).Bundle
	if out, err := Check(ctx, newEnv(t, newToy()), b); out != Inconclusive || err == nil {
		t.Fatalf("%v %v", out, err)
	}
}
