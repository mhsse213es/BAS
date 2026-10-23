package db

import (
	"context"
	"os"
	"testing"

	"github.com/audspect/bas/internal/k8sscenario"
)

// TestK8sScenarioAudit_RecordsRefusalAsDenied checks a refusal is written with the denied outcome.
func TestK8sScenarioAudit_RecordsRefusalAsDenied(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := EnsureSchema(ctx, pool); err != nil {
		t.Fatal(err)
	}
	runID := "audit-refused-" + t.Name()
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM audit_logs WHERE resource = $1`, runID) })

	err = NewK8sScenarioAudit(pool).Write(ctx, k8sscenario.Event{Type: k8sscenario.EventRefused, RunID: runID,
		Fields: map[string]string{"requester": "op-1", "reason": "no approval"}})
	if err != nil {
		t.Fatal(err)
	}
	var outcome, action string
	if err := pool.QueryRow(ctx, `SELECT outcome, action FROM audit_logs WHERE resource = $1`, runID).Scan(&outcome, &action); err != nil {
		t.Fatal(err)
	}
	if outcome != "denied" || action != k8sscenario.EventRefused {
		t.Fatalf("audit row = (%s, %s), want (denied, %s)", outcome, action, k8sscenario.EventRefused)
	}
}

// TestK8sScenarioAudit_FailsClosedWhenWriteFails checks a failed write is returned, so the engine stops.
func TestK8sScenarioAudit_FailsClosedWhenWriteFails(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	if err := NewK8sScenarioAudit(pool).Write(ctx, k8sscenario.Event{Type: k8sscenario.EventRequested, RunID: "x"}); err == nil {
		t.Fatal("a failed audit write must return an error so the engine does not proceed")
	}
}

func TestOutcomeOf(t *testing.T) {
	cases := map[string]struct {
		ev   k8sscenario.Event
		want string
	}{
		"refused":         {k8sscenario.Event{Type: k8sscenario.EventRefused}, "denied"},
		"requested":       {k8sscenario.Event{Type: k8sscenario.EventRequested}, "ok"},
		"cleaned":         {k8sscenario.Event{Type: k8sscenario.EventOutcome, Fields: map[string]string{"state": "CLEANED"}}, "ok"},
		"cleanup failed":  {k8sscenario.Event{Type: k8sscenario.EventOutcome, Fields: map[string]string{"state": "CLEANUP_FAILED"}}, "denied"},
		"outcome refusal": {k8sscenario.Event{Type: k8sscenario.EventOutcome, Fields: map[string]string{"state": "REFUSED"}}, "denied"},
	}
	for name, c := range cases {
		if got := outcomeOf(c.ev); got != c.want {
			t.Errorf("%s: outcomeOf = %q, want %q", name, got, c.want)
		}
	}
}
