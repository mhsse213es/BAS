package binding_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/binding"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/openapi"
	"github.com/audspect/bas/internal/apibas/runner"
)

const specYAML = `openapi: 3.0.0
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
  /v2/customers/{cid}/notes/{noteId}:
    get:
      responses: {"200": {description: ok}}
  /v2/products/{productId}:
    get:
      security: []
      responses: {"200": {description: ok}}
  /v2/invoices/{invoiceId}:
    get:
      responses: {"200": {description: ok}}
`

func inventory(t *testing.T) *openapi.Inventory {
	t.Helper()
	inv, err := openapi.Import([]byte(specYAML))
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func goodSpec() binding.Spec {
	return binding.Spec{
		Identities: []binding.IdentitySpec{
			{Name: "alice", CredentialRef: "shop/alice"},
			{Name: "bob", CredentialRef: "shop/bob"},
		},
		Objects: []binding.ObjectSpec{
			{Operation: "GET /v2/orders/{orderId}", Params: map[string]string{"orderId": "ORD-A1"}, Owner: "alice", ProtectedValues: []string{"alice-secret-note"}},
			{Operation: "GET /v2/orders/{orderId}", Params: map[string]string{"orderId": "ORD-B1"}, Owner: "bob", ProtectedValues: []string{"bob-secret-note"}},
			{Operation: "GET /v2/products/{productId}", Params: map[string]string{"productId": "P1"}, Owner: "alice"},
			{Operation: "GET /v2/invoices/{invoiceId}", Params: map[string]string{"invoiceId": "INV-1"}, Owner: "alice"},
		},
	}
}

func TestBindProducesValidReadOnlyScenarios(t *testing.T) {
	plan, err := binding.Bind(inventory(t), goodSpec())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Scenarios) != 2 {
		t.Fatalf("%d scenarios, want 2 (alice and bob each as the victim of the orders read)", len(plan.Scenarios))
	}
	for _, s := range plan.Scenarios {
		if err := s.Validate(); err != nil {
			t.Errorf("%s: %v", s.ID, err)
		}
		if s.SideEffectClass != "READ_ONLY" || s.Claim != "cross_identity" || !strings.HasPrefix(s.ID, "API-BAS-AUTHZ-9") {
			t.Errorf("%s: class %s claim %s", s.ID, s.SideEffectClass, s.Claim)
		}
		for _, st := range s.Steps {
			if st.Method != "GET" {
				t.Errorf("%s: step %s is %s", s.ID, st.ID, st.Method)
			}
		}
	}
	// The path is the operation's template with the supplied values; the attacker is the other identity.
	b := plan.Bound[0]
	if b.Path != "/v2/orders/ORD-A1" || b.Victim != "alice" || b.Attacker != "bob" {
		t.Errorf("first bound: %+v", b)
	}
	if len(plan.Limits) == 0 {
		t.Error("a plan must state its limits")
	}
}

func skipReason(plan *binding.Plan, op string) string {
	for _, s := range plan.Skipped {
		if s.Operation == op {
			return s.Reason
		}
	}
	return ""
}

func TestUnbindableOperationsAreReportedWithReasons(t *testing.T) {
	plan, err := binding.Bind(inventory(t), goodSpec())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"PATCH /v2/orders/{orderId}":             "changes state",
		"GET /v2/products/{productId}":           "public",
		"GET /v2/invoices/{invoiceId}":           "two different identities",
		"GET /v2/customers/{cid}/notes/{noteId}": "no test objects",
	}
	for op, want := range cases {
		if got := skipReason(plan, op); !strings.Contains(got, want) {
			t.Errorf("%s: reason %q, want it to mention %q", op, got, want)
		}
	}
}

func TestSpecValidation(t *testing.T) {
	inv := inventory(t)
	mut := func(f func(*binding.Spec)) binding.Spec { s := goodSpec(); f(&s); return s }
	cases := map[string]binding.Spec{
		"one identity":       mut(func(s *binding.Spec) { s.Identities = s.Identities[:1] }),
		"bad identity name":  mut(func(s *binding.Spec) { s.Identities[0].Name = "Alice Smith" }),
		"duplicate identity": mut(func(s *binding.Spec) { s.Identities[1].Name = "alice" }),
		"shared credential":  mut(func(s *binding.Spec) { s.Identities[1].CredentialRef = "shop/alice" }),
		"bad credential ref": mut(func(s *binding.Spec) { s.Identities[0].CredentialRef = "has space" }),
		"no objects":         mut(func(s *binding.Spec) { s.Objects = nil }),
		"unknown owner":      mut(func(s *binding.Spec) { s.Objects[0].Owner = "mallory" }),
		"unknown operation":  mut(func(s *binding.Spec) { s.Objects[0].Operation = "GET /nope/{id}" }),
		"missing param":      mut(func(s *binding.Spec) { s.Objects[0].Params = map[string]string{} }),
		"extra param":        mut(func(s *binding.Spec) { s.Objects[0].Params["other"] = "x" }),
		"traversal in value": mut(func(s *binding.Spec) { s.Objects[0].Params["orderId"] = "../admin" }),
		"slash in value":     mut(func(s *binding.Spec) { s.Objects[0].Params["orderId"] = "a/b" }),
		"query in value":     mut(func(s *binding.Spec) { s.Objects[0].Params["orderId"] = "a?x=1" }),
		"short protected":    mut(func(s *binding.Spec) { s.Objects[0].ProtectedValues = []string{"abc"} }),
		"newline protected":  mut(func(s *binding.Spec) { s.Objects[0].ProtectedValues = []string{"line1\nline2"} }),
		"duplicate object":   mut(func(s *binding.Spec) { s.Objects[1] = s.Objects[0] }),
	}
	for name, spec := range cases {
		if _, err := binding.Bind(inv, spec); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestScenarioLimit(t *testing.T) {
	spec := goodSpec()
	spec.Objects = nil
	for i := 0; i < 60; i++ {
		id := string(rune('a'+i%26)) + string(rune('a'+i/26)) + "-1"
		spec.Objects = append(spec.Objects,
			binding.ObjectSpec{Operation: "GET /v2/orders/{orderId}", Params: map[string]string{"orderId": "A" + id}, Owner: "alice"},
			binding.ObjectSpec{Operation: "GET /v2/orders/{orderId}", Params: map[string]string{"orderId": "B" + id}, Owner: "bob"})
	}
	if _, err := binding.Bind(inventory(t), spec); err == nil {
		t.Error("120 scenarios were accepted; the limit is 99")
	}
}

// ---- end to end: bound scenarios through the real runner against a spec-shaped API ----

type order struct{ owner, note string }

func shopServer(vulnerable bool) *httptest.Server {
	orders := map[string]order{
		"ORD-A1": {"alice", "alice-secret-note"},
		"ORD-B1": {"bob", "bob-secret-note"},
	}
	tokens := map[string]string{"tok-alice": "alice", "tok-bob": "bob"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v2/orders/{orderId}", func(w http.ResponseWriter, r *http.Request) {
		who, ok := tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !ok {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		o, found := orders[r.PathValue("orderId")]
		if !found || (!vulnerable && o.owner != who) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": r.PathValue("orderId"), "owner": o.owner, "note": o.note})
	})
	return httptest.NewServer(mux)
}

func runPlan(t *testing.T, vulnerable bool) []runner.Report {
	t.Helper()
	plan, err := binding.Bind(inventory(t), goodSpec())
	if err != nil {
		t.Fatal(err)
	}
	srv := shopServer(vulnerable)
	t.Cleanup(srv.Close)
	r, err := runner.New(runner.Config{
		BaseURL: srv.URL, Fixture: plan.Fixture,
		Secrets: runner.MapSecrets{"shop/alice": "tok-alice", "shop/bob": "tok-bob"},
		State:   runner.NoState{},
	})
	if err != nil {
		t.Fatal(err)
	}
	var out []runner.Report
	for _, s := range plan.Scenarios {
		rep, err := r.Run(context.Background(), s)
		if err != nil {
			t.Fatalf("%s: %v", s.ID, err)
		}
		out = append(out, rep)
	}
	return out
}

func TestBoundScenariosFindTheMissingOwnerCheck(t *testing.T) {
	for _, rep := range runPlan(t, true) {
		if rep.Outcome.Result != grade.FAIL || rep.Outcome.Exploitability != grade.Exploited {
			t.Errorf("%s against the vulnerable API: %s %s (%s %s), want FAIL exploited", rep.ScenarioID, rep.Outcome.Result,
				rep.Outcome.Exploitability, rep.Outcome.Reason, rep.Detail)
		}
	}
}

func TestBoundScenariosPassWhenTheOwnerCheckExists(t *testing.T) {
	for _, rep := range runPlan(t, false) {
		if rep.Outcome.Result != grade.PASS || rep.Outcome.Control != grade.Enforced {
			t.Errorf("%s against the fixed API: %s %s (%s %s), want PASS enforced", rep.ScenarioID, rep.Outcome.Result,
				rep.Outcome.Control, rep.Outcome.Reason, rep.Detail)
		}
	}
}

// NoState cannot see a state change, so the runner must refuse to grade any scenario that is not read-only with it.
func TestNoStateRefusesAScenarioThatChangesState(t *testing.T) {
	plan, err := binding.Bind(inventory(t), goodSpec())
	if err != nil {
		t.Fatal(err)
	}
	srv := shopServer(true)
	defer srv.Close()
	r, _ := runner.New(runner.Config{BaseURL: srv.URL, Fixture: plan.Fixture, Secrets: runner.MapSecrets{"shop/alice": "a", "shop/bob": "b"}, State: runner.NoState{}})
	s := plan.Scenarios[0]
	s.SideEffectClass = "STATE_CHANGE_SANDBOX"
	rep, err := r.Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Outcome.Result != grade.SKIPPED || rep.Outcome.Reason != grade.ReasonAdapterUnavailable {
		t.Errorf("got %s %s, want SKIPPED ADAPTER_UNAVAILABLE", rep.Outcome.Result, rep.Outcome.Reason)
	}
}

var _ = contract.Scenario{}
