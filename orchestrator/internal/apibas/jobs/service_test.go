package jobs

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/secretstore"
	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	sharedDB   *testutil.TestDB
	fakeRunner string
)

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "apibas-fakerunner-")
	if err != nil {
		panic(err)
	}
	fakeRunner = filepath.Join(dir, "fakerunner")
	if runtime.GOOS == "windows" {
		fakeRunner += ".exe" // Windows starts a child only from a file with this suffix
	}
	build := exec.Command("go", "build", "-o", fakeRunner, "./testdata/fakerunner")
	if out, err := build.CombinedOutput(); err != nil {
		panic("build fake runner: " + err.Error() + ": " + string(out))
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.RemoveAll(dir)
	os.Exit(code)
}

// newKey returns base64 of 32 random bytes, the format the secret store requires.
func newKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// setup returns a service on the shared database with a secret store holding one target credential.
func setup(t *testing.T, pool *pgxpool.Pool, cfg Config) (*Service, secretstore.Store, string) {
	t.Helper()
	ctx := context.Background()
	if err := db.EnsureSecretStoreSchema(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureAPIBASJobSchema(ctx, pool); err != nil {
		t.Fatal(err)
	}
	store, err := secretstore.NewPGStore(pool, newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := secretstore.MakeRef("apibas_targets", t.Name(), "token")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, ref, "expected-secret-value"); err != nil {
		t.Fatal(err)
	}
	cfg.RunnerPath = fakeRunner
	cfg.WorkDir = t.TempDir()
	svc, err := New(pool, store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return svc, store, ref
}

// spec builds a submission whose fixture selects the fake runner's behaviour.
func spec(key, behaviour, ref string) Spec {
	return Spec{
		Key: key, RequestedBy: "tester", TargetBaseURL: "http://127.0.0.1:8099", Environment: "lab",
		Fixture: behaviour, ScenarioIDs: []string{"API-BAS-AUTHZ-001"},
		Credentials: map[string]string{"apibas/lab/customer-a": ref},
	}
}

func jobOf(t *testing.T, s *Service, sp Spec) string {
	t.Helper()
	job, _, err := s.Submit(context.Background(), sp)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	return job.ID
}

func finalState(t *testing.T, pool *pgxpool.Pool, id string) (db.APIBASJob, []db.APIBASJobReport) {
	t.Helper()
	job, err := db.GetAPIBASJob(context.Background(), pool, id)
	if err != nil {
		t.Fatal(err)
	}
	reps, err := db.ListAPIBASJobReports(context.Background(), pool, id)
	if err != nil {
		t.Fatal(err)
	}
	return job, reps
}

func skipShort(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
}

func TestSubmitIsIdempotentOnKey(t *testing.T) {
	skipShort(t)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		svc, _, ref := setup(t, pool, Config{})
		first, created, err := svc.Submit(context.Background(), spec("idem-key-0001", "complete", ref))
		if err != nil || !created {
			t.Fatalf("first submit: created=%v err=%v", created, err)
		}
		second, created2, err := svc.Submit(context.Background(), spec("idem-key-0001", "complete", ref))
		if err != nil || created2 || second.ID != first.ID {
			t.Fatalf("second submit: id=%s created=%v err=%v; want the same job, not created", second.ID, created2, err)
		}
	})
}

func TestSubmitRefusesProductionAndPlaintextCredentials(t *testing.T) {
	skipShort(t)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		svc, _, ref := setup(t, pool, Config{})
		ctx := context.Background()

		prod := spec("prod-key-0001", "complete", ref)
		prod.Environment = "production"
		if _, _, err := svc.Submit(ctx, prod); !errors.Is(err, ErrEnvironmentNotPermitted) {
			t.Fatalf("production: err = %v, want ErrEnvironmentNotPermitted", err)
		}

		plain := spec("plain-key-0001", "complete", ref)
		plain.Credentials = map[string]string{"apibas/lab/customer-a": "sk-plaintext-secret"}
		if _, _, err := svc.Submit(ctx, plain); err == nil {
			t.Fatal("a plaintext credential was accepted in place of a secret-store reference")
		} else if strings.Contains(err.Error(), "sk-plaintext-secret") {
			t.Fatal("the refused plaintext credential appeared in the error text")
		}
	})
}

func TestCompletedDispatchPersistsReportsOnce(t *testing.T) {
	skipShort(t)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		svc, _, ref := setup(t, pool, Config{})
		ctx := context.Background()
		id := jobOf(t, svc, spec("complete-key-01", "complete", ref))

		started, err := svc.Dispatch(ctx, id)
		if err != nil || !started {
			t.Fatalf("dispatch: started=%v err=%v", started, err)
		}
		job, reps := finalState(t, pool, id)
		if job.Status != "completed" || job.FailureReason != "" {
			t.Fatalf("status = %s (%s), want completed", job.Status, job.FailureReason)
		}
		if len(reps) != 1 || reps[0].ScenarioID != "API-BAS-AUTHZ-001" || reps[0].Result != "FAIL" {
			t.Fatalf("reports = %+v, want one verdict for the scenario", reps)
		}

		// Retried dispatch: no second execution, no second set of reports.
		again, err := svc.Dispatch(ctx, id)
		if err != nil || again {
			t.Fatalf("second dispatch: started=%v err=%v; want not started", again, err)
		}
		_, reps2 := finalState(t, pool, id)
		if len(reps2) != 1 {
			t.Fatalf("reports after retry = %d, want 1", len(reps2))
		}
	})
}

// Every way the child can fail ends in a failed job with no reports. None may read as success.
func TestFailureModesNeverPersistReports(t *testing.T) {
	skipShort(t)
	cases := []struct {
		name, behaviour, reason string
	}{
		{"malformed output", "malformed", "malformed runner output"},
		{"mismatched job", "wrong-job", "runner result rejected"},
		{"runner reports failure", "runner-failed", "fixture refused by runner"},
		{"exit non-zero after a complete-looking document", "exit-nonzero", "runner exited with an error"},
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		svc, _, ref := setup(t, pool, Config{})
		ctx := context.Background()
		for i, c := range cases {
			id := jobOf(t, svc, spec("fail-key-000"+string(rune('a'+i)), c.behaviour, ref))
			if _, err := svc.Dispatch(ctx, id); err != nil {
				t.Fatalf("%s: dispatch: %v", c.name, err)
			}
			job, reps := finalState(t, pool, id)
			if job.Status != "failed" {
				t.Errorf("%s: status = %s, want failed", c.name, job.Status)
			}
			if len(reps) != 0 {
				t.Errorf("%s: %d reports stored for a failed job", c.name, len(reps))
			}
			if !strings.Contains(job.FailureReason, c.reason) {
				t.Errorf("%s: reason %q does not mention %q", c.name, job.FailureReason, c.reason)
			}
		}
	})
}

func TestTimeoutFailsTheJob(t *testing.T) {
	skipShort(t)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		svc, _, ref := setup(t, pool, Config{Timeout: 2 * time.Second})
		id := jobOf(t, svc, spec("hang-key-0001", "hang", ref))
		if _, err := svc.Dispatch(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		job, reps := finalState(t, pool, id)
		if job.Status != "failed" || job.FailureReason != "execution timed out" || len(reps) != 0 {
			t.Fatalf("status=%s reason=%q reports=%d; want failed by timeout with no reports", job.Status, job.FailureReason, len(reps))
		}
	})
}

func TestCancellationCancelsTheJob(t *testing.T) {
	skipShort(t)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		svc, _, ref := setup(t, pool, Config{Timeout: time.Minute})
		id := jobOf(t, svc, spec("cancel-key-001", "hang", ref))
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(time.Second, cancel)
		if _, err := svc.Dispatch(ctx, id); err != nil {
			t.Fatal(err)
		}
		job, reps := finalState(t, pool, id)
		if job.Status != "cancelled" || len(reps) != 0 {
			t.Fatalf("status=%s reports=%d; want cancelled with no reports", job.Status, len(reps))
		}
	})
}

func TestChildDoesNotInheritParentEnvironment(t *testing.T) {
	skipShort(t)
	t.Setenv("APIBAS_TEST_PARENT_SECRET", "must-not-reach-child")
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		svc, _, ref := setup(t, pool, Config{})
		id := jobOf(t, svc, spec("env-key-000001", "env-check", ref))
		if _, err := svc.Dispatch(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		job, _ := finalState(t, pool, id)
		if job.Status != "completed" {
			t.Fatalf("status = %s (%s): the child saw a parent variable it must not inherit", job.Status, job.FailureReason)
		}
	})
}

// The credential reaches the child as a file, the child can read it, the file is gone afterwards, and the value is never stored
// on the job.
func TestCredentialReachesChildThenIsRemoved(t *testing.T) {
	skipShort(t)
	marker := filepath.Join(t.TempDir(), "marker.txt")
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		svc, _, ref := setup(t, pool, Config{})
		id := jobOf(t, svc, spec("cred-key-000001", "creds-check:"+marker, ref))
		if _, err := svc.Dispatch(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		job, _ := finalState(t, pool, id)
		if job.Status != "completed" {
			t.Fatalf("status = %s (%s): the child could not read its credentials", job.Status, job.FailureReason)
		}
		recorded, err := os.ReadFile(marker)
		if err != nil {
			t.Fatal(err)
		}
		credsPath := string(recorded)
		if _, err := os.Stat(credsPath); !os.IsNotExist(err) {
			t.Fatalf("credentials file %s still exists after the job (err=%v)", credsPath, err)
		}
		row, err := pool.Query(context.Background(), `SELECT credential_refs::text FROM apibas_jobs WHERE id = $1::uuid`, id)
		if err != nil {
			t.Fatal(err)
		}
		defer row.Close()
		for row.Next() {
			var refs string
			if err := row.Scan(&refs); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(refs, "expected-secret-value") || !strings.Contains(refs, ref) {
				t.Fatalf("job record holds %s; want the reference, never the value", refs)
			}
		}
	})
}

func TestUnresolvableCredentialFailsBeforeRunning(t *testing.T) {
	skipShort(t)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		svc, _, _ := setup(t, pool, Config{})
		missing, _ := secretstore.MakeRef("apibas_targets", "absent-target", "token")
		id := jobOf(t, svc, spec("missing-key-0001", "complete", missing))
		if _, err := svc.Dispatch(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		job, reps := finalState(t, pool, id)
		if job.Status != "failed" || job.FailureReason != "target credential unavailable" || len(reps) != 0 {
			t.Fatalf("status=%s reason=%q reports=%d; want failed before running", job.Status, job.FailureReason, len(reps))
		}
	})
}

func TestStaleRunningJobsAreFailed(t *testing.T) {
	skipShort(t)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		svc, _, ref := setup(t, pool, Config{})
		ctx := context.Background()
		id := jobOf(t, svc, spec("stale-key-00001", "complete", ref))
		if _, err := pool.Exec(ctx, `UPDATE apibas_jobs SET status = 'running', started_at = NOW() - interval '2 hours' WHERE id = $1::uuid`, id); err != nil {
			t.Fatal(err)
		}
		n, err := svc.ReconcileStale(ctx, time.Hour)
		if err != nil || n < 1 {
			t.Fatalf("reconcile: n=%d err=%v", n, err)
		}
		job, _ := finalState(t, pool, id)
		if job.Status != "failed" || !strings.Contains(job.FailureReason, "orchestrator stopped") {
			t.Fatalf("status=%s reason=%q; want failed by reconciliation", job.Status, job.FailureReason)
		}
	})
}

// The store refuses a terminal state that breaks the report rules, whatever the caller does.
func TestStoreRefusesInconsistentTerminalStates(t *testing.T) {
	skipShort(t)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		svc, _, ref := setup(t, pool, Config{})
		ctx := context.Background()
		id := jobOf(t, svc, spec("store-key-00001", "complete", ref))
		if _, err := pool.Exec(ctx, `UPDATE apibas_jobs SET status = 'running', started_at = NOW() WHERE id = $1::uuid`, id); err != nil {
			t.Fatal(err)
		}
		if err := db.FinishAPIBASJob(ctx, pool, id, "completed", "", nil); err == nil {
			t.Fatal("a completed job with no reports was accepted")
		}
		if err := db.FinishAPIBASJob(ctx, pool, id, "failed", "", nil); err == nil {
			t.Fatal("a failed job with no reason was accepted")
		}
		rep := []db.APIBASJobReport{{ScenarioID: "API-BAS-AUTHZ-001", RunTag: "t", Result: "PASS", Report: []byte(`{}`)}}
		if err := db.FinishAPIBASJob(ctx, pool, id, "failed", "reason", rep); err == nil {
			t.Fatal("a failed job carrying reports was accepted")
		}
		if err := db.FinishAPIBASJob(ctx, pool, id, "completed", "", rep); err != nil {
			t.Fatalf("a valid completion was refused: %v", err)
		}
	})
}
