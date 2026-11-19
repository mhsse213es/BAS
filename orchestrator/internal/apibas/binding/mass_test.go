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
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/runner"
)

func massSpec() binding.Spec {
	return binding.Spec{
		AllowWrites: true,
		Identities:  []binding.IdentitySpec{{Name: "alice", CredentialRef: "shop/alice"}, {Name: "bob", CredentialRef: "shop/bob"}},
		MassAssignments: []binding.MassAssignSpec{{
			Operation: "PATCH /v2/orders/{orderId}", Params: map[string]string{"orderId": "ORD-A1"}, Owner: "alice",
			AttackBody:      `{"status":"shipped","role":"admin","price":"0"}`,
			ForbiddenFields: []string{"role", "price"},
			RestoreBody:     `{"status":"open","role":"user","price":"100"}`,
		}},
	}
}

func TestMassAssignmentBindsAsAnOwnerWriteWatchingOnlyTheForbiddenFields(t *testing.T) {
	plan, err := binding.Bind(writeInventory(t), massSpec())
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if len(plan.Scenarios) != 1 || !plan.Writes || !plan.Mass {
		t.Fatalf("plan: %d scenarios writes %v mass %v", len(plan.Scenarios), plan.Writes, plan.Mass)
	}
	sc := plan.Scenarios[0]
	if sc.Claim != "property_level" || sc.SideEffectClass != "STATE_CHANGE_SANDBOX" || len(sc.Cleanup) == 0 {
		t.Errorf("scenario: claim %s class %s cleanup %v", sc.Claim, sc.SideEffectClass, sc.Cleanup)
	}
	if sc.Steps[0].Identity != "alice" || sc.Steps[1].Identity != "alice" || sc.Steps[1].Method != "PATCH" || sc.Steps[1].Path != "/v2/orders/ORD-A1" {
		t.Errorf("steps: %+v", sc.Steps)
	}
	if len(plan.Probes) != 1 || strings.Join(plan.Probes[0].Watch, ",") != "role,price" || plan.Probes[0].Path != "/v2/orders/ORD-A1" {
		t.Errorf("probes: %+v", plan.Probes)
	}
	if len(plan.Restores) != 1 || plan.Restores[0].Body != massSpec().MassAssignments[0].RestoreBody {
		t.Errorf("restores: %+v", plan.Restores)
	}
	if !strings.Contains(strings.Join(plan.Limits, " "), "mass-assignment check") {
		t.Errorf("limits do not describe mass assignment: %v", plan.Limits)
	}
}

func TestMassAssignmentValidation(t *testing.T) {
	mut := map[string]func(*binding.Spec){
		"writes not allowed":     func(s *binding.Spec) { s.AllowWrites = false },
		"unknown owner":          func(s *binding.Spec) { s.MassAssignments[0].Owner = "eve" },
		"unknown operation":      func(s *binding.Spec) { s.MassAssignments[0].Operation = "PATCH /nope" },
		"not a write":            func(s *binding.Spec) { s.MassAssignments[0].Operation = "GET /v2/orders/{orderId}" },
		"missing param":          func(s *binding.Spec) { s.MassAssignments[0].Params = map[string]string{} },
		"bad param value":        func(s *binding.Spec) { s.MassAssignments[0].Params["orderId"] = "a/b" },
		"attack not JSON object": func(s *binding.Spec) { s.MassAssignments[0].AttackBody = `[1]` },
		"restore not JSON":       func(s *binding.Spec) { s.MassAssignments[0].RestoreBody = `nope` },
		"identical bodies":       func(s *binding.Spec) { s.MassAssignments[0].RestoreBody = s.MassAssignments[0].AttackBody },
		"no forbidden fields":    func(s *binding.Spec) { s.MassAssignments[0].ForbiddenFields = nil },
		"too many fields": func(s *binding.Spec) {
			s.MassAssignments[0].ForbiddenFields = strings.Split("a,b,c,d,e,f,g,h,i,j,k", ",")
		},
		"attack omits field": func(s *binding.Spec) { s.MassAssignments[0].ForbiddenFields = []string{"role", "isAdmin"} },
		"bad field name":     func(s *binding.Spec) { s.MassAssignments[0].ForbiddenFields = []string{"role.x"} },
		"duplicate field":    func(s *binding.Spec) { s.MassAssignments[0].ForbiddenFields = []string{"role", "role"} },
		"repeated check": func(s *binding.Spec) {
			s.MassAssignments = append(s.MassAssignments, s.MassAssignments[0])
		},
		"read route missing": func(s *binding.Spec) { s.MassAssignments[0].ReadOperation = "GET /nope" },
	}
	for name, f := range mut {
		s := massSpec()
		s.MassAssignments[0].Params = map[string]string{"orderId": "ORD-A1"}
		f(&s)
		if _, err := binding.Bind(writeInventory(t), s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type massAPI struct {
	mu     sync.Mutex
	mode   string // "vulnerable" sets forbidden fields, "ignoring" accepts and drops them, "strict" answers 422, "nofield" never returns them
	state  map[string]string
	tokens map[string]string
}

func newMassAPI(mode string) (*massAPI, *httptest.Server) {
	a := &massAPI{mode: mode, state: map[string]string{"status": "open", "role": "user", "price": "100"}, tokens: map[string]string{"tok-alice": "alice", "tok-bob": "bob"}}
	mux := http.NewServeMux()
	who := func(r *http.Request) string {
		return a.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	}
	mux.HandleFunc("GET /v2/orders/{orderId}", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if who(r) != "alice" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		out := map[string]any{"id": "ORD-A1", "status": a.state["status"], "updated_at": time.Now().UnixNano()}
		if a.mode != "nofield" {
			out["role"], out["price"] = a.state["role"], a.state["price"]
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("PATCH /v2/orders/{orderId}", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if who(r) != "alice" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var body map[string]string
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		_, hasRole := body["role"]
		if a.mode == "strict" && hasRole && body["role"] != a.state["role"] {
			http.Error(w, "unprocessable", http.StatusUnprocessableEntity)
			return
		}
		for k, v := range body {
			if k == "status" || a.mode == "vulnerable" || a.mode == "nofield" {
				a.state[k] = v
			}
		}
		w.WriteHeader(http.StatusOK)
	})
	return a, httptest.NewServer(mux)
}

func runMass(t *testing.T, mode string) ([]runner.Report, *massAPI) {
	t.Helper()
	plan, err := binding.Bind(writeInventory(t), massSpec())
	if err != nil {
		t.Fatal(err)
	}
	api, srv := newMassAPI(mode)
	t.Cleanup(srv.Close)
	secrets := runner.MapSecrets{"shop/alice": "tok-alice", "shop/bob": "tok-bob"}
	ref := func(identity string) string { id, _ := plan.Fixture.Identity(identity); return id.TokenRef }
	var probes []runner.Probe
	for _, p := range plan.Probes {
		probes = append(probes, runner.Probe{Key: p.Key, TokenRef: ref(p.Identity), Path: p.Path, Ignore: p.Ignore, Watch: p.Watch})
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
	return out, api
}

func TestMassAssignmentAgainstARealChangingAPI(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want grade.Result
	}{
		{"vulnerable", grade.FAIL},
		{"ignoring", grade.PASS},
		{"strict", grade.PASS},
		// The read route never returns the forbidden fields: a change could not be seen, so this is an error, never a pass.
		{"nofield", grade.ERROR},
	} {
		reps, api := runMass(t, tc.mode)
		for _, rep := range reps {
			if rep.Outcome.Result != tc.want {
				t.Errorf("%s: graded %s %s (%s), want %s", tc.mode, rep.Outcome.Result, rep.Outcome.Reason, rep.Detail, tc.want)
			}
			if rep.Reset != "ok" {
				t.Errorf("%s: cleanup %q", tc.mode, rep.Reset)
			}
		}
		if api.state["role"] != "user" || api.state["price"] != "100" || api.state["status"] != "open" {
			t.Errorf("%s: object left as %v", tc.mode, api.state)
		}
	}
}
