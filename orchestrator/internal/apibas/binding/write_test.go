package binding_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/audspect/bas/internal/apibas/binding"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/openapi"
	"github.com/audspect/bas/internal/apibas/runner"
)

const writeSpecYAML = `openapi: 3.0.0
info: {title: Shop, version: "1"}
security: [{bearer: []}]
paths:
  /v2/orders/{orderId}:
    get:
      parameters: [{name: orderId, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: ok}}
    patch:
      parameters: [{name: orderId, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: ok}}
    delete:
      parameters: [{name: orderId, in: path, required: true, schema: {type: string}}]
      responses: {"204": {description: gone}}
  /v2/orders/{orderId}/cancel:
    post:
      parameters: [{name: orderId, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: ok}}
`

func writeInventory(t *testing.T) *openapi.Inventory {
	t.Helper()
	inv, err := openapi.Import([]byte(writeSpecYAML))
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func writeBlock() *binding.WriteSpec {
	return &binding.WriteSpec{AttackBody: `{"status":"hacked"}`, RestoreBody: `{"status":"open"}`, IgnoreFields: []string{"updated_at"}}
}

func writeSpec() binding.Spec {
	return binding.Spec{
		AllowWrites: true,
		Identities: []binding.IdentitySpec{
			{Name: "alice", CredentialRef: "shop/alice"},
			{Name: "bob", CredentialRef: "shop/bob"},
		},
		Objects: []binding.ObjectSpec{
			{Operation: "PATCH /v2/orders/{orderId}", Params: map[string]string{"orderId": "ORD-A1"}, Owner: "alice", Write: writeBlock()},
			{Operation: "PATCH /v2/orders/{orderId}", Params: map[string]string{"orderId": "ORD-B1"}, Owner: "bob", Write: writeBlock()},
		},
	}
}

func TestWriteBindingProducesRestorableStateChangeScenarios(t *testing.T) {
	plan, err := binding.Bind(writeInventory(t), writeSpec())
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Writes || len(plan.Scenarios) != 2 || len(plan.Probes) != 2 || len(plan.Restores) != 2 {
		t.Fatalf("writes=%v scenarios=%d probes=%d restores=%d", plan.Writes, len(plan.Scenarios), len(plan.Probes), len(plan.Restores))
	}
	for _, s := range plan.Scenarios {
		if err := s.Validate(); err != nil {
			t.Errorf("%s: %v", s.ID, err)
		}
		if s.SideEffectClass != "STATE_CHANGE_SANDBOX" || len(s.Cleanup) == 0 {
			t.Errorf("%s: class %s cleanup %v", s.ID, s.SideEffectClass, s.Cleanup)
		}
		// The baseline reads the object; the attack is the other identity's write, with the supplied body.
		if s.Steps[0].Method != "GET" || s.Steps[1].Method != "PATCH" || s.Steps[1].Body != `{"status":"hacked"}` {
			t.Errorf("%s: steps %+v", s.ID, s.Steps)
		}
	}
	b := plan.Bound[0]
	if !b.Write || b.Path != "/v2/orders/ORD-A1" || b.Victim != "alice" || b.Attacker != "bob" {
		t.Errorf("bound: %+v", b)
	}
	if plan.Restores[0].Identity != "alice" || plan.Restores[0].Method != "PATCH" || plan.Restores[0].Body != `{"status":"open"}` || plan.Probes[0].Path != "/v2/orders/ORD-A1" {
		t.Errorf("probe/restore: %+v %+v", plan.Probes[0], plan.Restores[0])
	}
	if joined := strings.Join(plan.Limits, " "); !strings.Contains(joined, "restore request") || !strings.Contains(joined, "reading the object back") {
		t.Errorf("limits do not describe the write risk: %v", plan.Limits)
	}
	// A plan without writes does not carry the write limits.
	rp, err := binding.Bind(inventory(t), goodSpec())
	if err != nil {
		t.Fatal(err)
	}
	if rp.Writes || strings.Contains(strings.Join(rp.Limits, " "), "restore request") {
		t.Errorf("a read-only plan claims writes: %v", rp.Limits)
	}
}

func TestWriteOperationsThatCannotBeRestoredAreSkipped(t *testing.T) {
	spec := writeSpec()
	spec.Objects = append(spec.Objects,
		binding.ObjectSpec{Operation: "DELETE /v2/orders/{orderId}", Params: map[string]string{"orderId": "ORD-A1"}, Owner: "alice"},
		binding.ObjectSpec{Operation: "POST /v2/orders/{orderId}/cancel", Params: map[string]string{"orderId": "ORD-A1"}, Owner: "alice"})
	plan, err := binding.Bind(writeInventory(t), spec)
	if err != nil {
		t.Fatal(err)
	}
	if got := skipReason(plan, "DELETE /v2/orders/{orderId}"); !strings.Contains(got, "destroys") {
		t.Errorf("DELETE: %q", got)
	}
	if got := skipReason(plan, "POST /v2/orders/{orderId}/cancel"); !strings.Contains(got, "cannot be undone") {
		t.Errorf("POST: %q", got)
	}
	for _, s := range plan.Scenarios {
		if s.Steps[1].Method == "DELETE" || s.Steps[1].Method == "POST" {
			t.Errorf("%s binds a method that cannot be restored", s.ID)
		}
	}
}

func TestWriteSpecValidation(t *testing.T) {
	inv := writeInventory(t)
	mut := func(f func(*binding.Spec)) binding.Spec { s := writeSpec(); f(&s); return s }
	cases := map[string]binding.Spec{
		"writes not allowed":          mut(func(s *binding.Spec) { s.AllowWrites = false }),
		"write op without a block":    mut(func(s *binding.Spec) { s.Objects[0].Write = nil }),
		"block on a GET":              mut(func(s *binding.Spec) { s.Objects[0].Operation = "GET /v2/orders/{orderId}" }),
		"block on a DELETE":           mut(func(s *binding.Spec) { s.Objects[0].Operation = "DELETE /v2/orders/{orderId}" }),
		"attack body not JSON":        mut(func(s *binding.Spec) { s.Objects[0].Write.AttackBody = "status=hacked" }),
		"attack body an array":        mut(func(s *binding.Spec) { s.Objects[0].Write.AttackBody = `[1]` }),
		"attack body empty":           mut(func(s *binding.Spec) { s.Objects[0].Write.AttackBody = "" }),
		"restore body missing":        mut(func(s *binding.Spec) { s.Objects[0].Write.RestoreBody = "" }),
		"bodies identical":            mut(func(s *binding.Spec) { s.Objects[0].Write.RestoreBody = s.Objects[0].Write.AttackBody }),
		"body too large":              mut(func(s *binding.Spec) { s.Objects[0].Write.AttackBody = `{"a":"` + strings.Repeat("x", 5000) + `"}` }),
		"read operation unknown":      mut(func(s *binding.Spec) { s.Objects[0].Write.ReadOperation = "GET /nope/{orderId}" }),
		"read operation not a GET":    mut(func(s *binding.Spec) { s.Objects[0].Write.ReadOperation = "DELETE /v2/orders/{orderId}" }),
		"read operation other params": mut(func(s *binding.Spec) { s.Objects[0].Write.ReadOperation = "GET /v2/orders/{orderId}/cancel" }),
		"bad ignore field":            mut(func(s *binding.Spec) { s.Objects[0].Write.IgnoreFields = []string{"a b"} }),
		"too many ignore fields": mut(func(s *binding.Spec) {
			for i := 0; i < 21; i++ {
				s.Objects[0].Write.IgnoreFields = append(s.Objects[0].Write.IgnoreFields, "f"+string(rune('a'+i)))
			}
		}),
	}
	for name, spec := range cases {
		if _, err := binding.Bind(inv, spec); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// ---- through the real runner, against an API that really changes ----

type writableAPI struct {
	mu          sync.Mutex
	mode        string // "vulnerable", "fixed", "noop" (accepts the write, changes nothing), "restorefails"
	owner       map[string]string
	status      map[string]string
	tokens      map[string]string
	restoreFail bool
}

func newWritableAPI(mode string) (*writableAPI, *httptest.Server) {
	a := &writableAPI{
		mode:   mode,
		owner:  map[string]string{"ORD-A1": "alice", "ORD-B1": "bob"},
		status: map[string]string{"ORD-A1": "open", "ORD-B1": "open"},
		tokens: map[string]string{"tok-alice": "alice", "tok-bob": "bob"},
	}
	mux := http.NewServeMux()
	who := func(r *http.Request) string {
		return a.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	}
	mux.HandleFunc("GET /v2/orders/{orderId}", func(w http.ResponseWriter, r *http.Request) {
		me := who(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		id := r.PathValue("orderId")
		if me == "" || a.owner[id] != me {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		// updated_at changes on every read: the comparison must ignore it.
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "status": a.status[id], "updated_at": time.Now().UnixNano()})
	})
	mux.HandleFunc("PATCH /v2/orders/{orderId}", func(w http.ResponseWriter, r *http.Request) {
		me := who(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		id := r.PathValue("orderId")
		if me == "" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		if a.mode == "restorefails" && me == a.owner[id] {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		if a.mode != "vulnerable" && a.mode != "noop" && a.owner[id] != me {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var body map[string]string
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		if a.mode != "noop" || a.owner[id] == me {
			if v, ok := body["status"]; ok {
				a.status[id] = v
			}
		}
		w.WriteHeader(http.StatusOK)
	})
	return a, httptest.NewServer(mux)
}

func runWritePlan(t *testing.T, srv *httptest.Server, plan *binding.Plan) []runner.Report {
	t.Helper()
	secrets := runner.MapSecrets{"shop/alice": "tok-alice", "shop/bob": "tok-bob"}
	ref := func(identity string) string { id, _ := plan.Fixture.Identity(identity); return id.TokenRef }
	var probes []runner.Probe
	for _, p := range plan.Probes {
		probes = append(probes, runner.Probe{Key: p.Key, TokenRef: ref(p.Identity), Path: p.Path, Ignore: p.Ignore})
	}
	var restores []runner.Restore
	for _, r := range plan.Restores {
		restores = append(restores, runner.Restore{Key: r.Key, TokenRef: ref(r.Identity), Method: r.Method, Path: r.Path, Body: r.Body})
	}
	client := &http.Client{Timeout: 5 * time.Second}
	st, err := runner.NewHTTPState(srv.URL, probes, secrets, client, []string{"/v2"})
	if err != nil {
		t.Fatal(err)
	}
	rs, err := runner.NewHTTPRestore(srv.URL, restores, secrets, client, []string{"/v2"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := runner.New(runner.Config{BaseURL: srv.URL, Fixture: plan.Fixture, Secrets: secrets, State: st, Reset: rs, HTTP: client, AllowedPaths: []string{"/v2"}})
	if err != nil {
		t.Fatal(err)
	}
	var out []runner.Report
	for _, s := range plan.Scenarios {
		rep, err := r.Run(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rep)
	}
	return out
}

func TestWriteScenariosAgainstARealChangingAPI(t *testing.T) {
	plan, err := binding.Bind(writeInventory(t), writeSpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode       string
		want       grade.Result
		wantReason string
	}{
		{"vulnerable", grade.FAIL, ""},
		{"fixed", grade.PASS, ""},
		// The write is accepted but the owner's view does not change: neither a pass nor a failure.
		{"noop", grade.SKIPPED, string(grade.ReasonEvidenceInconclusive)},
	} {
		api, srv := newWritableAPI(tc.mode)
		reps := runWritePlan(t, srv, plan)
		srv.Close()
		for _, rep := range reps {
			if rep.Outcome.Result != tc.want {
				t.Errorf("%s: %s graded %s %s, want %s", tc.mode, rep.ScenarioID, rep.Outcome.Result, rep.Outcome.Reason, tc.want)
			}
			if tc.wantReason != "" && string(rep.Outcome.Reason) != tc.wantReason {
				t.Errorf("%s: reason %q, want %q", tc.mode, rep.Outcome.Reason, tc.wantReason)
			}
			if rep.Reset != "ok" {
				t.Errorf("%s: cleanup %q", tc.mode, rep.Reset)
			}
		}
		// Whatever the verdict, the objects are left as supplied: a successful write was undone by the restore.
		for id, st := range api.status {
			if st != "open" {
				t.Errorf("%s: %s was left as %q", tc.mode, id, st)
			}
		}
	}
}

func TestAFailedRestoreIsAnErrorNeverAPass(t *testing.T) {
	plan, err := binding.Bind(writeInventory(t), writeSpec())
	if err != nil {
		t.Fatal(err)
	}
	_, srv := newWritableAPI("restorefails")
	defer srv.Close()
	for _, rep := range runWritePlan(t, srv, plan) {
		if rep.Outcome.Result != grade.ERROR {
			t.Errorf("%s graded %s with a restore the target refuses; want ERROR", rep.ScenarioID, rep.Outcome.Result)
		}
	}
}

func TestStateReaderAndRestoreStayInsideAllowedPaths(t *testing.T) {
	client := &http.Client{Timeout: time.Second}
	secrets := runner.MapSecrets{"x": "t"}
	if _, err := runner.NewHTTPState("http://127.0.0.1:1", []runner.Probe{{Key: "k", TokenRef: "x", Path: "/admin/orders/1"}}, secrets, client, []string{"/v2"}); err == nil {
		t.Error("a probe outside the allowed paths was accepted")
	}
	if _, err := runner.NewHTTPRestore("http://127.0.0.1:1", []runner.Restore{{Key: "k", TokenRef: "x", Method: "PATCH", Path: "/admin/orders/1", Body: "{}"}}, secrets, client, []string{"/v2"}); err == nil {
		t.Error("a restore outside the allowed paths was accepted")
	}
}

// A write scenario must not run through the response-only reader: NoState cannot show a change, so the runner refuses.
func TestWriteScenarioWithNoStateIsRefused(t *testing.T) {
	plan, err := binding.Bind(writeInventory(t), writeSpec())
	if err != nil {
		t.Fatal(err)
	}
	_, srv := newWritableAPI("vulnerable")
	defer srv.Close()
	r, err := runner.New(runner.Config{BaseURL: srv.URL, Fixture: plan.Fixture, Secrets: runner.MapSecrets{"shop/alice": "tok-alice", "shop/bob": "tok-bob"}, State: runner.NoState{}})
	if err != nil {
		t.Fatal(err)
	}
	var s contract.Scenario = plan.Scenarios[0]
	rep, err := r.Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Outcome.Result != grade.SKIPPED || rep.Outcome.Reason != grade.ReasonAdapterUnavailable {
		t.Errorf("got %s %s", rep.Outcome.Result, rep.Outcome.Reason)
	}
}
