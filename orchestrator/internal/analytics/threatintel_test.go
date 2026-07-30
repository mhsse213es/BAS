package analytics

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/threatpriority"
)

func TestThreatIntelSummary_NilEngine_ReturnsEmptyActors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := ThreatIntelSummary(context.Background(), pool, nil)
		if err != nil {
			t.Fatalf("ThreatIntelSummary: %v", err)
		}
		if len(got.TopActors) != 0 {
			t.Errorf("TopActors = %+v, want empty when tpEngine is nil", got.TopActors)
		}
	})
}

func TestThreatIntelSummary_TopActorsClampedToFive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		names := []string{"Actor A", "Actor B", "Actor C", "Actor D", "Actor E", "Actor F"}
		for _, n := range names {
			mustExec(t, pool, `
				INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, confidence)
				VALUES ($1, '{}', '{}', '{}', 'medium')`, n)
		}
		eng := threatpriority.NewEngine(pool, scenario.NewEngine(t.TempDir()), nil, nil)

		got, err := ThreatIntelSummary(context.Background(), pool, eng)
		if err != nil {
			t.Fatalf("ThreatIntelSummary: %v", err)
		}
		if len(got.TopActors) != 5 {
			t.Errorf("TopActors = %d actors, want exactly 5 (clamped from 6 seeded profiles)", len(got.TopActors))
		}
	})
}

func TestThreatIntelSummary_FewerThanFiveActors_ReturnsAll(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `
			INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, confidence)
			VALUES ('Solo Actor', '{}', '{}', '{}', 'high')`)
		eng := threatpriority.NewEngine(pool, scenario.NewEngine(t.TempDir()), nil, nil)

		got, err := ThreatIntelSummary(context.Background(), pool, eng)
		if err != nil {
			t.Fatalf("ThreatIntelSummary: %v", err)
		}
		if len(got.TopActors) != 1 {
			t.Errorf("TopActors = %d actors, want 1 (only 1 profile seeded)", len(got.TopActors))
		}
	})
}

func TestThreatIntelSummary_KEVCounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO techniques (technique_id, name, tactic) VALUES ('T1059', 'Command and Scripting Interpreter', 'execution')`)
		mustExec(t, pool, `INSERT INTO art_atomic_tests (technique_id, test_index, name, executor, command) VALUES ('T1059', 1, 'Test 1', 'powershell', 'whoami')`)
		mustExec(t, pool, `INSERT INTO cves (cve_id, source, known_ransomware) VALUES ('CVE-2024-0001', 'cisa-kev', false)`)
		mustExec(t, pool, `INSERT INTO cves (cve_id, source, known_ransomware) VALUES ('CVE-2024-0002', 'cisa-kev', false)`)
		mustExec(t, pool, `INSERT INTO technique_cves (technique_id, cve_id) VALUES ('T1059', 'CVE-2024-0001')`)
		mustExec(t, pool, `INSERT INTO technique_cves (technique_id, cve_id) VALUES ('T1059', 'CVE-2024-0002')`)

		got, err := ThreatIntelSummary(context.Background(), pool, nil)
		if err != nil {
			t.Fatalf("ThreatIntelSummary: %v", err)
		}
		if got.KEVExposedTechniques != 1 {
			t.Errorf("KEVExposedTechniques = %d, want 1 (one technique, two CVEs)", got.KEVExposedTechniques)
		}
		if got.TotalKEVCVEs != 2 {
			t.Errorf("TotalKEVCVEs = %d, want 2", got.TotalKEVCVEs)
		}
	})
}
