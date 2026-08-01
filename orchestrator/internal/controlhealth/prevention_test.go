package controlhealth

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLoadPreventionEvidence_ReturnsRowsWithinWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('ch-a1', 'CH-HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('ch-run-1', 'ch-scn-1', 'CH Test Run', 'ch-a1', 'completed', $1::jsonb, NOW())`,
			`[
				{"technique":{"id":"T1059.001","name":"PowerShell","tactic":"execution"},"result":"pass","executedAt":"2026-07-25T10:00:00Z"},
				{"technique":{"id":"T1003","name":"OS Credential Dumping","tactic":"credential-access"},"result":"fail","executedAt":"2026-07-26T10:00:00Z"},
				{"technique":{"id":"T1078","name":"Valid Accounts","tactic":"defense-evasion"},"result":"skipped","executedAt":"2026-07-26T10:00:00Z"}
			]`)

		since := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
		got, err := loadPreventionEvidence(ctx, pool, since)
		if err != nil {
			t.Fatalf("loadPreventionEvidence: %v", err)
		}
		var sawT1059, sawT1003, sawT1078 bool
		for _, r := range got {
			switch r.TechniqueID {
			case "T1059":
				sawT1059 = true
				if r.Verdict != "pass" {
					t.Errorf("T1059 verdict = %q, want pass", r.Verdict)
				}
			case "T1003":
				sawT1003 = true
				if r.Verdict != "fail" {
					t.Errorf("T1003 verdict = %q, want fail", r.Verdict)
				}
			case "T1078":
				sawT1078 = true
			}
		}
		if !sawT1059 {
			t.Error("expected T1059.001 to be normalized to base T1059 and returned")
		}
		if !sawT1003 {
			t.Error("expected T1003 to be returned")
		}
		if sawT1078 {
			t.Error("skipped result must be excluded, but T1078 was returned")
		}
	})
}

func TestLoadPreventionEvidence_ExcludesRowsBeforeWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('ch-a2', 'CH-HOST-2')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('ch-run-2', 'ch-scn-2', 'CH Old Run', 'ch-a2', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1566","name":"Phishing","tactic":"initial-access"},"result":"pass","executedAt":"2020-01-01T00:00:00Z"}]`)

		since := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
		got, err := loadPreventionEvidence(ctx, pool, since)
		if err != nil {
			t.Fatalf("loadPreventionEvidence: %v", err)
		}
		for _, r := range got {
			if r.TechniqueID == "T1566" {
				t.Error("2020 result must be excluded by the since cutoff, but T1566 was returned")
			}
		}
	})
}
