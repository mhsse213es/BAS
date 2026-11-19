package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/audspect/bas/internal/apibas/binding"
	"github.com/audspect/bas/internal/apibas/openapi"
	"github.com/audspect/bas/internal/apibas/runnerproto"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/secretstore"
	"github.com/jackc/pgx/v5/pgxpool"
)

const boundWriteYAML = `openapi: 3.0.0
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
`

func boundWritePlan(t *testing.T) runnerproto.BoundPlan {
	t.Helper()
	inv, err := openapi.Import([]byte(boundWriteYAML))
	if err != nil {
		t.Fatal(err)
	}
	w := func() *binding.WriteSpec {
		return &binding.WriteSpec{AttackBody: `{"status":"hacked"}`, RestoreBody: `{"status":"open"}`, IgnoreFields: []string{"updated_at"}}
	}
	return runnerproto.BoundPlan{InventoryVersion: 1, Inventory: *inv, Spec: binding.Spec{
		AllowWrites: true,
		Identities:  []binding.IdentitySpec{{Name: "alice", CredentialRef: "shop/alice"}, {Name: "bob", CredentialRef: "shop/bob"}},
		Objects: []binding.ObjectSpec{
			{Operation: "PATCH /v2/orders/{orderId}", Params: map[string]string{"orderId": "ORD-A1"}, Owner: "alice", Write: w()},
			{Operation: "PATCH /v2/orders/{orderId}", Params: map[string]string{"orderId": "ORD-B1"}, Owner: "bob", Write: w()},
		},
	}}
}

type writableShop struct {
	mu     sync.Mutex
	status map[string]string
}

func newWritableShop(vulnerable bool, tokens map[string]string) (*writableShop, *httptest.Server) {
	a := &writableShop{status: map[string]string{"ORD-A1": "open", "ORD-B1": "open"}}
	owner := map[string]string{"ORD-A1": "alice", "ORD-B1": "bob"}
	who := map[string]string{tokens["shop/alice"]: "alice", tokens["shop/bob"]: "bob"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v2/orders/{orderId}", func(w http.ResponseWriter, r *http.Request) {
		me := who[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		a.mu.Lock()
		defer a.mu.Unlock()
		id := r.PathValue("orderId")
		if me == "" || owner[id] != me {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "status": a.status[id], "updated_at": time.Now().UnixNano()})
	})
	mux.HandleFunc("PATCH /v2/orders/{orderId}", func(w http.ResponseWriter, r *http.Request) {
		me := who[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		a.mu.Lock()
		defer a.mu.Unlock()
		id := r.PathValue("orderId")
		if me == "" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		if !vulnerable && owner[id] != me {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var body map[string]string
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		if v, ok := body["status"]; ok {
			a.status[id] = v
		}
	})
	return a, httptest.NewServer(mux)
}

// Write scenarios as a job, end to end with the real runner binary: the vulnerable API is graded FAIL and then left as supplied, the
// fixed API PASS; a target with no registered paths and a production target are refused before anything is stored.
func TestBoundWriteJobEndToEnd(t *testing.T) {
	skipShort(t)
	bin := t.TempDir()
	runnerBin := buildBinary(t, bin, "github.com/audspect/bas/cmd/apibas-runner", "apibas-runner")
	tokens := map[string]string{"shop/alice": "write-token-alice-" + t.Name(), "shop/bob": "write-token-bob-" + t.Name()}

	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		svc, store, _ := setup(t, pool, Config{RunnerPath: runnerBin, Timeout: 3 * time.Minute})
		svc.cfg.RunnerPath = runnerBin
		refs := map[string]string{}
		for name, v := range tokens {
			ref, err := secretstore.MakeRef("apibas_targets", "write-creds", sanitize(name))
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Put(ctx, ref, v); err != nil {
				t.Fatal(err)
			}
			refs[name] = ref
		}
		register := func(id, url, env string, paths []string) {
			t.Helper()
			if err := db.CreateAPIBASTarget(ctx, pool, db.APIBASTarget{
				ID: id, Name: id, BaseURL: url, Environment: env, AllowedHosts: []string{strings.TrimPrefix(url, "http://")}, AllowedPaths: paths,
				AllowedScenarios: []string{"API-BAS-AUTHZ-001"}, CredentialRefs: refs, Enabled: true, CreatedBy: "e2e",
			}); err != nil {
				t.Fatal(err)
			}
		}
		submit := func(target, key string) (db.APIBASJob, bool, error) {
			plan := boundWritePlan(t)
			return svc.SubmitForTarget(ctx, TargetRequest{Key: key, RequestedBy: "e2e", TargetID: target, Bound: &plan})
		}

		for _, tc := range []struct {
			name       string
			vulnerable bool
			want       string
		}{{"bw-vulnerable", true, "FAIL"}, {"bw-fixed", false, "PASS"}} {
			shop, srv := newWritableShop(tc.vulnerable, tokens)
			t.Cleanup(srv.Close)
			register(tc.name, srv.URL, "lab", []string{"/v2"})
			job, _, err := submit(tc.name, "key-"+tc.name)
			if err != nil {
				t.Fatalf("%s: submit: %v", tc.name, err)
			}
			if _, err := svc.Dispatch(ctx, job.ID); err != nil {
				t.Fatalf("%s: dispatch: %v", tc.name, err)
			}
			got, reps := finalState(t, pool, job.ID)
			if got.Status != "completed" || len(reps) != 2 {
				t.Fatalf("%s: status=%s (%s) reports=%d", tc.name, got.Status, got.FailureReason, len(reps))
			}
			for _, r := range reps {
				if r.Result != tc.want {
					t.Errorf("%s: %s graded %s (%s), want %s", tc.name, r.ScenarioID, r.Result, r.Reason, tc.want)
				}
			}
			shop.mu.Lock()
			for id, st := range shop.status {
				if st != "open" {
					t.Errorf("%s: %s was left as %q after the job", tc.name, id, st)
				}
			}
			shop.mu.Unlock()
		}

		srv := httptest.NewServer(http.NotFoundHandler())
		t.Cleanup(srv.Close)
		// Writes need registered path prefixes, even on a lab target.
		register("bw-nopaths", srv.URL, "lab", nil)
		if _, _, err := submit("bw-nopaths", "key-nopaths"); !errors.Is(err, ErrScopeViolation) {
			t.Errorf("writes with no allowed paths: %v, want a scope violation", err)
		}
		// A write plan is never attempted against production, even where production execution is enabled.
		svc.cfg.AllowProduction = true
		register("bw-prod", srv.URL, "production", []string{"/v2"})
		if _, _, err := submit("bw-prod", "key-prod"); !errors.Is(err, ErrEnvironmentNotPermitted) {
			t.Errorf("writes against production: %v, want the environment refused", err)
		}
		svc.cfg.AllowProduction = false
	})
}
