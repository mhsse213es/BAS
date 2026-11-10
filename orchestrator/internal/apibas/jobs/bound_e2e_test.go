package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/apibas/binding"
	"github.com/audspect/bas/internal/apibas/openapi"
	"github.com/audspect/bas/internal/apibas/runnerproto"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/secretstore"
	"github.com/jackc/pgx/v5/pgxpool"
)

const boundSpecYAML = `openapi: 3.0.0
info: {title: Shop, version: "1"}
security: [{bearer: []}]
paths:
  /v2/orders/{orderId}:
    get:
      parameters: [{name: orderId, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: ok}}
`

func boundPlan(t *testing.T) runnerproto.BoundPlan {
	t.Helper()
	inv, err := openapi.Import([]byte(boundSpecYAML))
	if err != nil {
		t.Fatal(err)
	}
	return runnerproto.BoundPlan{
		InventoryVersion: 1, Inventory: *inv,
		Spec: binding.Spec{
			Identities: []binding.IdentitySpec{{Name: "alice", CredentialRef: "shop/alice"}, {Name: "bob", CredentialRef: "shop/bob"}},
			Objects: []binding.ObjectSpec{
				{Operation: "GET /v2/orders/{orderId}", Params: map[string]string{"orderId": "ORD-A1"}, Owner: "alice", ProtectedValues: []string{"alice-secret-note"}},
				{Operation: "GET /v2/orders/{orderId}", Params: map[string]string{"orderId": "ORD-B1"}, Owner: "bob", ProtectedValues: []string{"bob-secret-note"}},
			},
		},
	}
}

// shopAPI is a customer-shaped API with no lab endpoints at all: a real runner can only judge it by its responses.
func shopAPI(vulnerable bool, tokens map[string]string) *httptest.Server {
	owner := map[string]string{"ORD-A1": "alice", "ORD-B1": "bob"}
	note := map[string]string{"ORD-A1": "alice-secret-note", "ORD-B1": "bob-secret-note"}
	who := map[string]string{tokens["shop/alice"]: "alice", tokens["shop/bob"]: "bob"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v2/orders/{orderId}", func(w http.ResponseWriter, r *http.Request) {
		me, ok := who[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !ok {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		id := r.PathValue("orderId")
		if _, found := owner[id]; !found || (!vulnerable && owner[id] != me) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "owner": owner[id], "note": note[id]})
	})
	return httptest.NewServer(mux)
}

// A customer-bound job, end to end through the real runner binary: the vulnerable API is graded FAIL and the fixed API PASS for the
// same bound scenarios; a plan altered after submission, a credential not on the target, and a path outside the target's scope are
// each refused.
func TestBoundJobEndToEnd(t *testing.T) {
	skipShort(t)
	bin := t.TempDir()
	runnerBin := buildBinary(t, bin, "github.com/audspect/bas/cmd/apibas-runner", "apibas-runner")
	tokens := map[string]string{"shop/alice": "bound-token-alice-" + t.Name(), "shop/bob": "bound-token-bob-" + t.Name()}

	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		svc, store, _ := setup(t, pool, Config{RunnerPath: runnerBin, Timeout: 3 * time.Minute})
		svc.cfg.RunnerPath = runnerBin
		refs := map[string]string{}
		for name, v := range tokens {
			ref, err := secretstore.MakeRef("apibas_targets", "bound-creds", sanitize(name))
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Put(ctx, ref, v); err != nil {
				t.Fatal(err)
			}
			refs[name] = ref
		}
		register := func(id, url string, paths []string, credRefs map[string]string) {
			t.Helper()
			host := strings.TrimPrefix(url, "http://")
			if err := db.CreateAPIBASTarget(ctx, pool, db.APIBASTarget{
				ID: id, Name: id, BaseURL: url, Environment: "lab", AllowedHosts: []string{host}, AllowedPaths: paths,
				AllowedScenarios: []string{"API-BAS-AUTHZ-001"}, CredentialRefs: credRefs, Enabled: true, CreatedBy: "e2e",
			}); err != nil {
				t.Fatal(err)
			}
		}
		submit := func(target, key string, plan runnerproto.BoundPlan) (db.APIBASJob, bool, error) {
			return svc.SubmitForTarget(ctx, TargetRequest{Key: key, RequestedBy: "e2e", TargetID: target, Bound: &plan})
		}

		for _, tc := range []struct {
			name       string
			vulnerable bool
			want       string
		}{{"bound-vulnerable", true, "FAIL"}, {"bound-fixed", false, "PASS"}} {
			srv := shopAPI(tc.vulnerable, tokens)
			t.Cleanup(srv.Close)
			register(tc.name, srv.URL, []string{"/v2"}, refs)
			plan := boundPlan(t)
			job, created, err := submit(tc.name, "key-"+tc.name, plan)
			if err != nil || !created {
				t.Fatalf("%s: submit: %v created=%v", tc.name, err, created)
			}
			if !runnerproto.IsBoundFixture(job.Fixture) || len(job.ScenarioIDs) != 2 {
				t.Fatalf("%s: fixture %q scenarios %v", tc.name, job.Fixture, job.ScenarioIDs)
			}
			// A repeated key returns the same job and stores nothing new.
			again, created2, err := submit(tc.name, "key-"+tc.name, plan)
			if err != nil || created2 || again.ID != job.ID {
				t.Fatalf("%s: replay: %v created=%v id=%s", tc.name, err, created2, again.ID)
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
					t.Errorf("%s: %s graded %s, want %s", tc.name, r.ScenarioID, r.Result, tc.want)
				}
			}
		}

		// A credential the target does not carry is refused at submission.
		srv := shopAPI(false, tokens)
		t.Cleanup(srv.Close)
		register("bound-nocred", srv.URL, []string{"/v2"}, map[string]string{"shop/alice": refs["shop/alice"]})
		if _, _, err := submit("bound-nocred", "key-nocred", boundPlan(t)); !errors.Is(err, ErrScopeViolation) {
			t.Errorf("unregistered credential: %v, want a scope violation", err)
		}

		// The target's path scope bounds a bound job like any other: the job fails and stores no report.
		register("bound-narrow", srv.URL, []string{"/health"}, refs)
		job, _, err := submit("bound-narrow", "key-narrow", boundPlan(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Dispatch(ctx, job.ID); err != nil {
			t.Fatal(err)
		}
		if got, reps := finalState(t, pool, job.ID); got.Status != "failed" || !strings.Contains(got.FailureReason, "outside") || len(reps) != 0 {
			t.Errorf("narrow scope: status=%s reason=%q reports=%d", got.Status, got.FailureReason, len(reps))
		}

		// A plan changed after submission no longer matches the fixture hash the job (and any approval) is bound to.
		register("bound-tamper", srv.URL, []string{"/v2"}, refs)
		job, _, err = submit("bound-tamper", "key-tamper", boundPlan(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE apibas_job_plans SET plan = jsonb_set(plan, '{spec,objects,0,params,orderId}', '"ORD-B1"') WHERE job_id = $1`, job.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Dispatch(ctx, job.ID); err != nil {
			t.Fatal(err)
		}
		if got, reps := finalState(t, pool, job.ID); got.Status != "failed" || !strings.Contains(got.FailureReason, "does not match") || len(reps) != 0 {
			t.Errorf("tampered plan: status=%s reason=%q reports=%d", got.Status, got.FailureReason, len(reps))
		}

		// A job whose plan row is missing fails instead of running.
		register("bound-noplan", srv.URL, []string{"/v2"}, refs)
		job, _, err = submit("bound-noplan", "key-noplan", boundPlan(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM apibas_job_plans WHERE job_id = $1`, job.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Dispatch(ctx, job.ID); err != nil {
			t.Fatal(err)
		}
		if got, _ := finalState(t, pool, job.ID); got.Status != "failed" || !strings.Contains(got.FailureReason, "plan is unavailable") {
			t.Errorf("missing plan: status=%s reason=%q", got.Status, got.FailureReason)
		}
	})
}
