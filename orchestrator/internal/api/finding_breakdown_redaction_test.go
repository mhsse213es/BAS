package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/findings"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting/attackdata"
)

// A finding's variant breakdown lists each step's details. A credential-access
// step's details must not appear there.
func TestVariantBreakdownForFinding_CredentialAccessDetailWithheld(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		results := []models.SimulationResult{{
			ID:        "fb-cred",
			Technique: models.AttackTechnique{ID: "T1003.001", Tactic: "credential-access"},
			Result:    models.CheckResult("fail"),
			Details:   "dumped NTLM " + exportTestNTLMHash,
		}}
		raw, err := json.Marshal(results)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		seedAgent(t, pool, "agent-fb-redact")
		var runID string
		if err := pool.QueryRow(t.Context(),
			`INSERT INTO scenario_runs (scenario_id, agent_id, name, status, results)
			 VALUES ('scn-fb', 'agent-fb-redact', 'Finding Breakdown Run', 'completed', $1) RETURNING id`, raw,
		).Scan(&runID); err != nil {
			t.Fatalf("seed scenario_run: %v", err)
		}

		var ds []string
		if e := attackdata.Lookup("T1003.001"); e != nil {
			ds = e.DataSources
		}
		h := New(pool, nil, nil, "")
		bd := h.variantBreakdownForFinding(context.Background(), runID, "T1003.001", findings.ControlClass(ds))
		if bd == nil {
			t.Fatal("breakdown is nil; the seeded fail should be counted")
		}
		body, err := json.Marshal(bd)
		if err != nil {
			t.Fatalf("marshal breakdown: %v", err)
		}
		if strings.Contains(string(body), exportTestNTLMHash) {
			t.Fatal("finding breakdown leaked a credential-access hash")
		}
	})
}
