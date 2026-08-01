package controlhealth

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/verification"
)

func TestComputeSummary_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mapper, err := NewMapper()
		if err != nil {
			t.Fatalf("NewMapper: %v", err)
		}

		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('ch-e2e-a1', 'CH-E2E-HOST')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('ch-e2e-run', 'ch-e2e-scn', 'CH E2E Run', 'ch-e2e-a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1566","name":"Phishing","tactic":"initial-access"},"result":"pass","executedAt":"`+time.Now().UTC().Format(time.RFC3339)+`"}]`)
		seedVerificationRecord(t, pool, "ch-e2e-vh", "T1566", verification.ResultDetected, verification.StateApproved, true, time.Now().UTC())

		out, err := ComputeSummary(ctx, pool, mapper, 30)
		if err != nil {
			t.Fatalf("ComputeSummary: %v", err)
		}
		if len(out) != 10 {
			t.Fatalf("got %d categories, want 10", len(out))
		}
		var email CategoryHealth
		for _, c := range out {
			if c.ID == "email-security" {
				email = c
			}
		}
		if email.PreventionHealth != "pass" {
			t.Errorf("email-security.PreventionHealth = %q, want pass", email.PreventionHealth)
		}
		if email.DetectionHealth != "pass" {
			t.Errorf("email-security.DetectionHealth = %q, want pass", email.DetectionHealth)
		}
		if email.EvidenceCount == 0 {
			t.Error("expected non-zero EvidenceCount for email-security")
		}
		if email.LastValidated == nil {
			t.Error("expected LastValidated to be set")
		}
	})
}
