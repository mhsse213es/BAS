package binding_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/binding"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/openapi"
	"github.com/audspect/bas/internal/apibas/runner"
)

const fpSpecYAML = `openapi: 3.0.0
info: {title: Shop, version: "1"}
security: [{bearer: []}]
paths:
  /v2/admin/reports/{reportId}:
    get:
      responses: {"200": {description: ok}}
  /v2/profiles/{pid}:
    get:
      responses: {"200": {description: ok}}
  /v2/public/{pid}:
    get:
      security: []
      responses: {"200": {description: ok}}
  /v2/profiles/{pid}/reset:
    post:
      responses: {"200": {description: ok}}
`

func fpInventory(t *testing.T) *openapi.Inventory {
	t.Helper()
	inv, err := openapi.Import([]byte(fpSpecYAML))
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func fpSpec() binding.Spec {
	return binding.Spec{
		Identities: []binding.IdentitySpec{{Name: "admin", CredentialRef: "shop/admin"}, {Name: "alice", CredentialRef: "shop/alice"}},
		Functions: []binding.FunctionSpec{{
			Operation: "GET /v2/admin/reports/{reportId}", Params: map[string]string{"reportId": "R-1"},
			Privileged: "admin", Ordinary: "alice", ProtectedValues: []string{"quarterly-revenue-secret"},
		}},
		Properties: []binding.PropertySpec{{
			Operation: "GET /v2/profiles/{pid}", Params: map[string]string{"pid": "P-ALICE"},
			Owner: "alice", ForbiddenValues: []string{"internal-risk-flag-77"},
		}},
	}
}

func TestFunctionAndPropertyChecksBindToReadOnlyScenarios(t *testing.T) {
	plan, err := binding.Bind(fpInventory(t), fpSpec())
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if len(plan.Scenarios) != 2 || len(plan.Bound) != 2 || plan.Writes {
		t.Fatalf("plan: %d scenarios, %d bound, writes %v", len(plan.Scenarios), len(plan.Bound), plan.Writes)
	}
	fn, pr := plan.Scenarios[0], plan.Scenarios[1]
	if fn.Claim != "function_level" || fn.Steps[0].Identity != "admin" || fn.Steps[1].Identity != "alice" || fn.SideEffectClass != "READ_ONLY" {
		t.Errorf("function scenario: %+v", fn)
	}
	if fn.Steps[1].Method != "GET" || fn.Steps[1].Path != "/v2/admin/reports/R-1" || len(fn.ForbiddenValues) != 1 {
		t.Errorf("function attack step: %+v", fn.Steps[1])
	}
	if pr.Claim != "property_level" || pr.Steps[0].Identity != "alice" || pr.Steps[1].Identity != "alice" || !pr.CleanIsEnforced {
		t.Errorf("property scenario: %+v", pr)
	}
	if plan.Bound[0].Kind != "function" || plan.Bound[0].Attacker != "alice" || plan.Bound[0].Victim != "admin" || plan.Bound[1].Kind != "property" {
		t.Errorf("bound: %+v", plan.Bound)
	}
	if !strings.Contains(strings.Join(plan.Limits, " "), "mass assignment") {
		t.Errorf("the limits do not say mass assignment is not tested: %v", plan.Limits)
	}
	// The objects exist in the fixture owned by the identity that makes the baseline call.
	owners := map[string]string{}
	for _, o := range plan.Fixture.Objects {
		owners[o.ID] = o.OwnerID
	}
	if owners[fn.Preconditions.Object] != "admin" || owners[pr.Preconditions.Object] != "alice" {
		t.Errorf("fixture owners: %v", owners)
	}
}

func TestFunctionAndPropertyAloneAreEnough(t *testing.T) {
	s := fpSpec()
	s.Objects = nil
	if _, err := binding.Bind(fpInventory(t), s); err != nil {
		t.Errorf("a spec with only function and property checks was refused: %v", err)
	}
	s.Functions, s.Properties = nil, nil
	if _, err := binding.Bind(fpInventory(t), s); err == nil {
		t.Error("a spec with nothing to test was accepted")
	}
}

func TestFunctionAndPropertyValidation(t *testing.T) {
	mutate := map[string]func(*binding.Spec){
		"unknown privileged": func(s *binding.Spec) { s.Functions[0].Privileged = "nobody" },
		"unknown ordinary":   func(s *binding.Spec) { s.Functions[0].Ordinary = "nobody" },
		"same identity":      func(s *binding.Spec) { s.Functions[0].Ordinary = "admin" },
		"not in inventory":   func(s *binding.Spec) { s.Functions[0].Operation = "GET /v2/nothing/{x}" },
		"not a GET": func(s *binding.Spec) {
			s.Functions[0].Operation = "POST /v2/profiles/{pid}/reset"
			s.Functions[0].Params = map[string]string{"pid": "P1"}
		},
		"public operation": func(s *binding.Spec) {
			s.Functions[0].Operation = "GET /v2/public/{pid}"
			s.Functions[0].Params = map[string]string{"pid": "P1"}
		},
		"missing param":        func(s *binding.Spec) { s.Functions[0].Params = nil },
		"extra param":          func(s *binding.Spec) { s.Functions[0].Params["other"] = "x1" },
		"bad param value":      func(s *binding.Spec) { s.Functions[0].Params["reportId"] = "../etc" },
		"no protected value":   func(s *binding.Spec) { s.Functions[0].ProtectedValues = nil },
		"short protected":      func(s *binding.Spec) { s.Functions[0].ProtectedValues = []string{"abc"} },
		"multiline protected":  func(s *binding.Spec) { s.Functions[0].ProtectedValues = []string{"line1\nline2"} },
		"duplicate function":   func(s *binding.Spec) { s.Functions = append(s.Functions, s.Functions[0]) },
		"unknown owner":        func(s *binding.Spec) { s.Properties[0].Owner = "nobody" },
		"property not a GET":   func(s *binding.Spec) { s.Properties[0].Operation = "POST /v2/profiles/{pid}/reset" },
		"property public":      func(s *binding.Spec) { s.Properties[0].Operation = "GET /v2/public/{pid}" },
		"no forbidden value":   func(s *binding.Spec) { s.Properties[0].ForbiddenValues = nil },
		"short forbidden":      func(s *binding.Spec) { s.Properties[0].ForbiddenValues = []string{"x"} },
		"too many values":      func(s *binding.Spec) { s.Properties[0].ForbiddenValues = make([]string, 21) },
		"duplicate property":   func(s *binding.Spec) { s.Properties = append(s.Properties, s.Properties[0]) },
		"property missing arg": func(s *binding.Spec) { s.Properties[0].Params = map[string]string{} },
	}
	for name, f := range mutate {
		s := fpSpec()
		f(&s)
		if _, err := binding.Bind(fpInventory(t), s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFunctionAndPropertySpecRoundTripsAsJSON(t *testing.T) {
	raw, err := json.Marshal(fpSpec())
	if err != nil {
		t.Fatal(err)
	}
	var back binding.Spec
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Functions) != 1 || back.Functions[0].Ordinary != "alice" || len(back.Properties) != 1 || back.Properties[0].ForbiddenValues[0] != "internal-risk-flag-77" {
		t.Errorf("round trip: %+v", back)
	}
}

// fpServer is a spec-shaped API. Vulnerable: any identity can read the admin report, and the profile carries an internal value.
func fpServer(vulnerable bool) *httptest.Server {
	tokens := map[string]string{"tok-admin": "admin", "tok-alice": "alice"}
	who := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		u, ok := tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !ok {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
		}
		return u, ok
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v2/admin/reports/{reportId}", func(w http.ResponseWriter, r *http.Request) {
		u, ok := who(w, r)
		if !ok {
			return
		}
		if !vulnerable && u != "admin" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": r.PathValue("reportId"), "revenue": "quarterly-revenue-secret"})
	})
	mux.HandleFunc("GET /v2/profiles/{pid}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := who(w, r); !ok {
			return
		}
		body := map[string]string{"id": r.PathValue("pid"), "name": "Alice"}
		if vulnerable {
			body["risk"] = "internal-risk-flag-77"
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	return httptest.NewServer(mux)
}

func runFP(t *testing.T, vulnerable bool) []runner.Report {
	t.Helper()
	plan, err := binding.Bind(fpInventory(t), fpSpec())
	if err != nil {
		t.Fatal(err)
	}
	srv := fpServer(vulnerable)
	t.Cleanup(srv.Close)
	r, err := runner.New(runner.Config{
		BaseURL: srv.URL, Fixture: plan.Fixture,
		Secrets: runner.MapSecrets{"shop/admin": "tok-admin", "shop/alice": "tok-alice"}, State: runner.NoState{},
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

func TestFunctionAndPropertyChecksFindTheFlaws(t *testing.T) {
	for _, rep := range runFP(t, true) {
		if rep.Outcome.Result != grade.FAIL || rep.Outcome.Exploitability != grade.Exploited {
			t.Errorf("%s against the flawed API: %s %s (%s %s), want FAIL exploited", rep.ScenarioID, rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason, rep.Detail)
		}
	}
}

func TestFunctionAndPropertyChecksPassWhenControlsExist(t *testing.T) {
	for _, rep := range runFP(t, false) {
		if rep.Outcome.Result != grade.PASS || rep.Outcome.Control != grade.Enforced {
			t.Errorf("%s against the fixed API: %s %s (%s %s), want PASS enforced", rep.ScenarioID, rep.Outcome.Result, rep.Outcome.Control, rep.Outcome.Reason, rep.Detail)
		}
	}
}
