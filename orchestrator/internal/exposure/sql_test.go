package exposure

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func approxEqual(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 0.001
}

func TestSQLCVEEnricher_JoinsKEVAndEPSS(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO cves (cve_id, cvss, source) VALUES ('CVE-2024-9001', 9.8, 'cisa-kev')`)
		mustExec(t, pool, `INSERT INTO cve_epss (cve_id, epss_score, percentile) VALUES ('CVE-2024-9001', 0.87, 0.99)`)
		mustExec(t, pool, `INSERT INTO cves (cve_id, cvss, source) VALUES ('CVE-2024-9002', 4.0, 'nvd')`)
		// CVE-2024-9002 has no cve_epss row — Enrich must not fail, just default to 0.

		enricher := NewSQLCVEEnricher(pool)
		meta, err := enricher.Enrich(context.Background(), []string{"CVE-2024-9001", "CVE-2024-9002", "CVE-2024-NOPE"})
		if err != nil {
			t.Fatalf("Enrich: %v", err)
		}
		if len(meta) != 2 {
			t.Fatalf("expected 2 entries (unknown CVE absent), got %+v", meta)
		}
		m1 := meta["CVE-2024-9001"]
		// cvss/epss_score are `real` (float32) columns — a decimal literal like
		// 9.8 cannot round-trip exactly through float32, so compare with a
		// small epsilon rather than exact equality.
		if !m1.KEV || !approxEqual(m1.CVSS, 9.8) || !approxEqual(m1.EPSSScore, 0.87) {
			t.Fatalf("CVE-2024-9001 = %+v, want KEV=true CVSS=~9.8 EPSS=~0.87", m1)
		}
		m2 := meta["CVE-2024-9002"]
		if m2.KEV || !approxEqual(m2.CVSS, 4.0) || m2.EPSSScore != 0 {
			t.Fatalf("CVE-2024-9002 = %+v, want KEV=false CVSS=~4.0 EPSS=0 (no epss row)", m2)
		}
	})
}

func TestSQLCVEEnricher_EmptyInputReturnsEmptyMap(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		enricher := NewSQLCVEEnricher(pool)
		meta, err := enricher.Enrich(context.Background(), nil)
		if err != nil {
			t.Fatalf("Enrich: %v", err)
		}
		if len(meta) != 0 {
			t.Fatalf("expected empty map, got %+v", meta)
		}
	})
}

func TestSQLFindingsLookup_GroupsByAgentSortedBySeverity(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname, ip_address, os_version, status, state, last_update)
			VALUES ('exp-fa-01', 'EXPFA01', '10.0.0.9', 'Windows 11', 'idle', 'active', NOW())`)
		mustExec(t, pool, `INSERT INTO findings (id, agent_id, technique_id, control_class, technique_name, tactic,
			severity, exposure_state, status, source_type, first_seen, last_seen)
			VALUES ('exp-f-1', 'exp-fa-01', 'T1059.001', 'prevention', 'PowerShell', 'execution',
			'Medium', 'Detected', 'open', 'simulation', NOW(), NOW())`)
		mustExec(t, pool, `INSERT INTO findings (id, agent_id, technique_id, control_class, technique_name, tactic,
			severity, exposure_state, status, source_type, first_seen, last_seen)
			VALUES ('exp-f-2', 'exp-fa-01', 'T1078', 'prevention', 'Valid Accounts', 'defense-evasion',
			'Critical', 'Missed', 'open', 'simulation', NOW(), NOW())`)
		mustExec(t, pool, `INSERT INTO findings (id, agent_id, technique_id, control_class, technique_name, tactic,
			severity, exposure_state, status, source_type, first_seen, last_seen)
			VALUES ('exp-f-3', 'exp-fa-01', 'T1021.002', 'prevention', 'SMB', 'lateral-movement',
			'High', 'Missed', 'resolved', 'simulation', NOW(), NOW())`)

		lookup := NewSQLFindingsLookup(pool)
		out, err := lookup.AllOpenFindings(context.Background())
		if err != nil {
			t.Fatalf("AllOpenFindings: %v", err)
		}
		list := out["exp-fa-01"]
		if len(list) != 2 {
			t.Fatalf("expected 2 open findings (resolved one excluded), got %+v", list)
		}
		if list[0].Severity != "Critical" {
			t.Fatalf("expected Critical severity first, got %+v", list[0])
		}
	})
}
