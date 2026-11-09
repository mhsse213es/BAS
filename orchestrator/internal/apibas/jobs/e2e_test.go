package jobs

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/secretstore"
	"github.com/jackc/pgx/v5/pgxpool"
)

// buildBinary compiles one command from this module into dir and returns its path.
func buildBinary(t *testing.T, dir, importPath, name string) string {
	t.Helper()
	out := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	if b, err := exec.Command("go", "build", "-o", out, importPath).CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", importPath, err, b)
	}
	return out
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// startLab runs the real apibas-lab binary in the given mode and waits until it accepts connections.
func startLab(t *testing.T, labBin, mode, addr string, tokens map[string]string) {
	t.Helper()
	cmd := exec.Command(labBin, "-mode", mode, "-fixture", "orders-two-tenant", "-addr", addr)
	cmd.Env = append(os.Environ(),
		"APIBAS_CUSTOMER_A_TOKEN="+tokens["apibas/lab/customer-a"],
		"APIBAS_CUSTOMER_B_TOKEN="+tokens["apibas/lab/customer-b"],
		"APIBAS_LAB_ADMIN_TOKEN="+tokens["apibas/lab/admin"])
	if err := cmd.Start(); err != nil {
		t.Fatalf("start lab: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("lab %s did not start on %s", mode, addr)
}

// A real job, end to end: the orchestrator service resolves credentials from the secret store, starts the real runner binary as a
// child process with an empty environment, the runner drives the real lab over HTTP, and the validated result is stored. The
// vulnerable build must be graded FAIL and the fixed build PASS for the same scenario.
func TestEndToEndRealRunnerAgainstRealLab(t *testing.T) {
	skipShort(t)
	bin := t.TempDir()
	runnerBin := buildBinary(t, bin, "github.com/audspect/bas/cmd/apibas-runner", "apibas-runner")
	labBin := buildBinary(t, bin, "github.com/audspect/bas/cmd/apibas-lab", "apibas-lab")
	tokens := map[string]string{
		"apibas/lab/customer-a": "e2e-token-customer-a-" + t.Name(),
		"apibas/lab/customer-b": "e2e-token-customer-b-" + t.Name(),
		"apibas/lab/admin":      "e2e-token-admin-" + t.Name(),
	}

	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		svc, store, _ := setup(t, pool, Config{RunnerPath: runnerBin, Timeout: 3 * time.Minute})
		svc.cfg.RunnerPath = runnerBin

		refs := map[string]string{}
		for name, value := range tokens {
			ref, err := secretstore.MakeRef("apibas_targets", "e2e-creds", sanitize(name))
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Put(ctx, ref, value); err != nil {
				t.Fatal(err)
			}
			refs[name] = ref
		}

		for _, tc := range []struct {
			mode, target, want string
		}{
			{"vulnerable", "e2e-vulnerable", "FAIL"},
			{"fixed", "e2e-fixed", "PASS"},
		} {
			addr := freeAddr(t)
			startLab(t, labBin, tc.mode, addr, tokens)
			if err := db.CreateAPIBASTarget(ctx, pool, db.APIBASTarget{
				ID: tc.target, Name: tc.target, BaseURL: "http://" + addr, Environment: "lab",
				AllowedHosts: []string{addr}, AllowedScenarios: []string{"API-BAS-AUTHZ-001"},
				CredentialRefs: refs, Enabled: true, CreatedBy: "e2e",
			}); err != nil {
				t.Fatal(err)
			}
			job, _, err := svc.SubmitForTarget(ctx, TargetRequest{
				Key: "e2e-key-" + tc.mode, RequestedBy: "e2e", TargetID: tc.target,
				Fixture: "orders-two-tenant", ScenarioIDs: []string{"API-BAS-AUTHZ-001"},
			})
			if err != nil {
				t.Fatalf("%s: submit: %v", tc.mode, err)
			}
			if _, err := svc.Dispatch(ctx, job.ID); err != nil {
				t.Fatalf("%s: dispatch: %v", tc.mode, err)
			}
			got, reps := finalState(t, pool, job.ID)
			if got.Status != "completed" {
				t.Fatalf("%s: status = %s (%s), want completed", tc.mode, got.Status, got.FailureReason)
			}
			if len(reps) != 1 || reps[0].Result != tc.want {
				t.Fatalf("%s: reports = %+v, want one report graded %s", tc.mode, reps, tc.want)
			}
			t.Logf("%s build: result=%s exploitability=%s control=%s detection=%s", tc.mode,
				reps[0].Result, reps[0].Exploitability, reps[0].Control, reps[0].Detection)
		}
	})
}

// sanitize turns a secret name into the lower-case column form the reference grammar accepts.
func sanitize(name string) string {
	out := []byte(name)
	for i, c := range out {
		if (c < 'a' || c > 'z') && c != '_' {
			out[i] = '_'
		}
	}
	return string(out)
}

// The runner compares bare hostnames, so registered host:port values must lose the port, including IPv6 literals.
func TestHostnamesStripsPorts(t *testing.T) {
	got := hostnames([]string{"192.168.10.78:9543", "api.example.test", "[::1]:8099", ""})
	want := []string{"192.168.10.78", "api.example.test", "::1"}
	if len(got) != len(want) {
		t.Fatalf("hostnames = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("hostnames = %v, want %v", got, want)
		}
	}
}
