package runner_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/lab"
)

// DATA-011 is a Phase 5 scenario. The runner resets the lab after every run, so the persisted state is read here, between
// the steps and the reset. Per build, the test checks:
//   - persisted state: whether the erased order is still in the lab's record store
//   - subsequent readability: the status of the owner's read after the erasure request
//   - protected values: whether that read carries the erased order's protected value
//
// The vulnerable build acknowledges the erasure and keeps the record, so the owner still reads it. The fixed build removes the
// record, so the read is 404. The runner's verdict is checked last, from its own run.
func TestPhase5_DATA011ErasureRetention(t *testing.T) {
	s := scenarioByID(t, "API-BAS-DATA-011")
	fx := fixtureFor(t, s.Preconditions.Fixture)
	ctx := context.Background()
	const erased, protected = "ORD-2001", "BAS-SIM-2001"
	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		e := newEnvWith(t, mode, fx, s.Preconditions.LabFaults, false)
		if err := e.admin.Reset(ctx); err != nil {
			t.Fatalf("%s: reset: %v", modeName(mode), err)
		}
		tok, err := e.secrets.Resolve("apibas/lab/customer-b")
		if err != nil {
			t.Fatalf("%s: customer-b token: %v", modeName(mode), err)
		}
		owner := func(method, path string) (int, string) {
			req, _ := http.NewRequestWithContext(ctx, method, e.srv.URL+path, strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("Content-Type", "application/json")
			resp, err := e.srv.Client().Do(req)
			if err != nil {
				t.Fatalf("%s %s: %v", modeName(mode), path, err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(b)
		}

		if st, _ := owner(http.MethodGet, "/api/orders/"+erased); st != 200 {
			t.Fatalf("%s: owner's baseline read status %d, want 200", modeName(mode), st)
		}
		owner(http.MethodPost, "/api/orders/"+erased+"/erase")

		snap, err := e.admin.Snapshot(ctx)
		if err != nil {
			t.Fatalf("%s: state snapshot: %v", modeName(mode), err)
		}
		_, persisted := snap[erased]
		readStatus, readBody := owner(http.MethodGet, "/api/orders/"+erased)
		leaked := strings.Contains(readBody, protected)

		if mode == lab.ModeVulnerable {
			if !persisted {
				t.Errorf("vulnerable: the erased order is gone from state; the build should retain it")
			}
			if readStatus != 200 || !leaked {
				t.Errorf("vulnerable: read after erasure status %d leaked=%t; want 200 with the protected value readable",
					readStatus, leaked)
			}
		} else {
			if persisted {
				t.Errorf("fixed: the erased order is still in state; the erasure did not remove it")
			}
			if readStatus != 404 || leaked {
				t.Errorf("fixed: read after erasure status %d leaked=%t; want 404 with no protected value", readStatus, leaked)
			}
		}

		rep := e.run(t, s, e.state)
		want := "FAIL"
		if mode == lab.ModeFixed {
			want = "PASS"
		}
		if string(rep.Outcome.Result) != want {
			t.Errorf("%s: runner result %s, want %s (exploitability %s, control %s)",
				modeName(mode), rep.Outcome.Result, want, rep.Outcome.Exploitability, rep.Outcome.Control)
		}
	}
}
