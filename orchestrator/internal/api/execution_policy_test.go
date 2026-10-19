package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// policyScenario stores one scenario and connects a stand-in agent. Dispatch
// then writes the run row and sends the command, which is captured on the
// returned channel. The agent's OS and the step's executor match, so dispatch
// does not skip the run.
func policyScenario(t *testing.T, pool *pgxpool.Pool) (*Handler, *scenario.Scenario, <-chan []byte) {
	t.Helper()
	ctx := context.Background()
	e, _, _ := registryEngine(t, pool)
	if err := e.SaveAs(ctx, &scenario.Scenario{ID: "policy-x", Name: "Policy X", Steps: []scenario.Step{
		{Name: "s1", TechniqueID: "T1059", Framework: "custom", Executor: "bash", Command: "echo 1"}}}, "user:op"); err != nil {
		t.Fatal(err)
	}
	seedAgent(t, pool, "pol-agent")
	if _, err := pool.Exec(ctx, `UPDATE agents SET os_version='Ubuntu 22.04 Linux' WHERE agent_id='pol-agent'`); err != nil {
		t.Fatal(err)
	}
	hub := ws.NewHub()
	cmds := hub.RegisterTestAgent("pol-agent")
	h := New(pool, hub, e, "")
	sc, ok := e.Get("policy-x")
	if !ok {
		t.Fatal("policy-x not stored")
	}
	return h, sc, cmds
}

// sentInProcessPolicy returns the inProcessPolicy of the scenario command that
// dispatch sent to the agent.
func sentInProcessPolicy(t *testing.T, cmds <-chan []byte) string {
	t.Helper()
	select {
	case raw := <-cmds:
		var msg models.WSMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			t.Fatalf("decode sent message: %v", err)
		}
		data, err := json.Marshal(msg.Data)
		if err != nil {
			t.Fatalf("re-encode command payload: %v", err)
		}
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(data, &cmd); err != nil {
			t.Fatalf("decode scenario command: %v", err)
		}
		return cmd.InProcessPolicy
	case <-time.After(5 * time.Second):
		t.Fatal("no command was sent to the agent")
	}
	return ""
}

func setDefault(t *testing.T, h *Handler, value string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.PutExecutionPolicyDefault(rec, httptest.NewRequest(http.MethodPut, "/api/execution-policy/default",
		strings.NewReader(`{"inProcessPolicy":"`+value+`"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("set default %q: status %d body %s", value, rec.Code, rec.Body.String())
	}
}

func snapshotOf(t *testing.T, pool *pgxpool.Pool, runID string) string {
	t.Helper()
	var v string
	if err := pool.QueryRow(context.Background(),
		`SELECT inprocess_policy FROM scenario_runs WHERE id = $1`, runID).Scan(&v); err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	return v
}

// The default endpoint reports an unset default as not stated, stores only
// documented values, and rejects anything else without changing the default.
func TestExecutionPolicyDefault_RoundTripAndValidation(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _, _ := policyScenario(t, pool)

		get := func() string {
			rec := httptest.NewRecorder()
			h.GetExecutionPolicyDefault(rec, httptest.NewRequest(http.MethodGet, "/api/execution-policy/default", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("GET status %d body %s", rec.Code, rec.Body.String())
			}
			return rec.Body.String()
		}
		if got := get(); !strings.Contains(got, `"inProcessPolicy":""`) {
			t.Fatalf("unset default must read as not stated, got %s", got)
		}

		setDefault(t, h, "restricted")
		if got := get(); !strings.Contains(got, `"inProcessPolicy":"restricted"`) {
			t.Fatalf("after PUT restricted, GET = %s", got)
		}

		rec := httptest.NewRecorder()
		h.PutExecutionPolicyDefault(rec, httptest.NewRequest(http.MethodPut, "/api/execution-policy/default",
			strings.NewReader(`{"inProcessPolicy":"strict"}`)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid value: status %d, want 400", rec.Code)
		}
		if got := get(); !strings.Contains(got, `"inProcessPolicy":"restricted"`) {
			t.Fatalf("rejected PUT must not change the default, got %s", got)
		}
	})
}

// Each dispatch sends the policy it was judged against to the agent, and stores
// the same value on the run. The value is the explicit one when given, else the
// installation default, else not stated.
func TestDispatchRun_PropagatesEffectivePolicy(t *testing.T) {
	cases := []struct {
		name     string
		dflt     string
		explicit string
		want     string
	}{
		{"explicit overrides default", "restricted", "unrestricted", "unrestricted"},
		{"inherits default when not stated", "restricted", "", "restricted"},
		{"neither set stays not stated", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
				h, sc, cmds := policyScenario(t, pool)
				if c.dflt != "" {
					setDefault(t, h, c.dflt)
				}
				runID, skip, err := h.dispatchRun(context.Background(), sc, "pol-agent",
					dispatchOpts{Mode: "posture", InProcessPolicy: c.explicit})
				if err != nil || runID == "" {
					t.Fatalf("dispatch: run=%q skip=%q err=%v", runID, skip, err)
				}
				if got := sentInProcessPolicy(t, cmds); got != c.want {
					t.Errorf("sent policy = %q, want %q", got, c.want)
				}
				if got := snapshotOf(t, pool, runID); got != c.want {
					t.Errorf("stored snapshot = %q, want %q", got, c.want)
				}
			})
		})
	}
}

// A later change to the installation default must not rewrite a run that was
// already dispatched. The snapshot is what that run was judged against.
func TestDispatchRun_SnapshotSurvivesDefaultChange(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, sc, cmds := policyScenario(t, pool)
		setDefault(t, h, "restricted")
		runID, _, err := h.dispatchRun(context.Background(), sc, "pol-agent", dispatchOpts{Mode: "posture"})
		if err != nil || runID == "" {
			t.Fatalf("dispatch: run=%q err=%v", runID, err)
		}
		_ = sentInProcessPolicy(t, cmds)
		setDefault(t, h, "unrestricted")
		if got := snapshotOf(t, pool, runID); got != "restricted" {
			t.Errorf("snapshot changed to %q after default change, want restricted", got)
		}
	})
}

// An invalid explicit value is an error that records nothing. It is never
// replaced by the default.
func TestDispatchRun_InvalidExplicitPolicyRecordsNothing(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, sc, _ := policyScenario(t, pool)
		setDefault(t, h, "restricted")
		runID, _, err := h.dispatchRun(context.Background(), sc, "pol-agent",
			dispatchOpts{Mode: "posture", InProcessPolicy: "strict"})
		if err == nil || runID != "" {
			t.Fatalf("want error and no run, got run=%q err=%v", runID, err)
		}
		var n int
		_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM scenario_runs`).Scan(&n)
		if n != 0 {
			t.Fatalf("invalid policy wrote %d run rows, want 0", n)
		}
	})
}
