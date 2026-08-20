package reporting

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func priorityMustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func priorityBySeedTechnique(t *testing.T, pool *pgxpool.Pool, id, name, tactic string) {
	t.Helper()
	priorityMustExec(t, pool, `INSERT INTO techniques (technique_id, name, tactic) VALUES ($1, $2, $3)`, id, name, tactic)
}

// seedKEVRelationship links techID to a CISA-KEV CVE via an Active/High
// relationship — the exact shape populatePriorityScores' KEV query requires.
func seedKEVRelationship(t *testing.T, pool *pgxpool.Pool, techID, cveID, confidence, status string) {
	t.Helper()
	priorityMustExec(t, pool, `INSERT INTO cves (cve_id, cvss, source) VALUES ($1, 9.8, 'cisa-kev') ON CONFLICT (cve_id) DO NOTHING`, cveID)
	priorityMustExec(t, pool, `
		INSERT INTO technique_cve_relationships
			(technique_id, cve_id, relationship_type, status, effective_confidence, primary_source)
		VALUES ($1, $2, 'Commonly Associated', $3, $4, 'CISA-KEV')`, techID, cveID, status, confidence)
}

// seedEPSSRelationship links techID to a non-KEV CVE carrying an EPSS score,
// via an Active/High relationship — the shape the EPSS query requires.
func seedEPSSRelationship(t *testing.T, pool *pgxpool.Pool, techID, cveID string, epssScore, percentile float64) {
	t.Helper()
	priorityMustExec(t, pool, `INSERT INTO cves (cve_id, cvss, source) VALUES ($1, 7.5, 'nvd') ON CONFLICT (cve_id) DO NOTHING`, cveID)
	priorityMustExec(t, pool, `INSERT INTO cve_epss (cve_id, epss_score, percentile) VALUES ($1, $2, $3) ON CONFLICT (cve_id) DO NOTHING`, cveID, epssScore, percentile)
	priorityMustExec(t, pool, `
		INSERT INTO technique_cve_relationships
			(technique_id, cve_id, relationship_type, status, effective_confidence, primary_source)
		VALUES ($1, $2, 'Commonly Associated', 'Active', 'High', 'NVD')`, techID, cveID)
}

func priorityOf(priorities []TechniquePriority, techID string) (TechniquePriority, bool) {
	for _, p := range priorities {
		if p.TechniqueID == techID {
			return p, true
		}
	}
	return TechniquePriority{}, false
}

// TestPopulatePriorityScores_EmptyMatrixNoOp proves the function returns
// before touching the DB at all when there's nothing to score — safe to call
// with a nil pool.
func TestPopulatePriorityScores_EmptyMatrixNoOp(t *testing.T) {
	e := NewEngine(nil)
	report := &FullReport{}
	e.populatePriorityScores(context.Background(), report)
	if report.PriorityScores != nil {
		t.Errorf("PriorityScores = %+v, want nil for an empty technique matrix", report.PriorityScores)
	}
}

// TestPopulatePriorityScores_KEVAndEPSSRankedAndSorted seeds one
// KEV-linked failing technique and one EPSS-linked passing technique, then
// verifies the composite score, tier, provenance fields, and the
// score-descending sort all come out of the real SQL wiring correctly.
func TestPopulatePriorityScores_KEVAndEPSSRankedAndSorted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		// T9901/T9902 are fictional IDs, deliberately outside real ATT&CK's
		// numbering range — real technique IDs (e.g. T1003) are used by dozens
		// of groups in the embedded attack_enrichment.json, which would add an
		// uncontrolled actor-count bonus on top of the KEV/EPSS signal under
		// test and make the expected scores non-deterministic.
		priorityBySeedTechnique(t, pool, "T9901", "Fictional Credential Dumping", "credential-access")
		seedKEVRelationship(t, pool, "T9901", "CVE-2024-0001", "High", "Active")

		priorityBySeedTechnique(t, pool, "T9902", "Fictional Process Injection", "defense-evasion")
		seedEPSSRelationship(t, pool, "T9902", "CVE-2024-0002", 0.91, 0.91)

		e := NewEngine(pool)
		report := &FullReport{TechniqueMatrix: []TechniqueRow{
			{TechniqueID: "T9901", TechniqueName: "Fictional Credential Dumping", Tactic: "credential-access", ExecVerdict: "fail"},
			{TechniqueID: "T9902", TechniqueName: "Fictional Process Injection", Tactic: "defense-evasion", ExecVerdict: "pass"},
		}}
		e.populatePriorityScores(context.Background(), report)

		if len(report.PriorityScores) != 2 {
			t.Fatalf("PriorityScores = %+v, want 2 entries", report.PriorityScores)
		}

		// T9901: KEV(+40) + fail bonus(+10) = 50, Critical tier is >=70 so this
		// lands in High (40-69) — assert the exact score the SQL produced.
		t9901, ok := priorityOf(report.PriorityScores, "T9901")
		if !ok {
			t.Fatal("T9901 missing from PriorityScores")
		}
		if !t9901.KEV || t9901.KEVCount != 1 {
			t.Errorf("T9901 KEV=%v KEVCount=%d, want true/1", t9901.KEV, t9901.KEVCount)
		}
		if t9901.PriorityScore != 50 {
			t.Errorf("T9901 PriorityScore = %d, want 50 (KEV 40 + fail bonus 10)", t9901.PriorityScore)
		}
		if t9901.PriorityTier != PriorityTierFor(50) {
			t.Errorf("T9901 PriorityTier = %q, want %q", t9901.PriorityTier, PriorityTierFor(50))
		}
		if t9901.RelationshipCount != 1 || t9901.PrimarySource != "CISA-KEV" {
			t.Errorf("T9901 provenance = count=%d source=%q, want count=1 source=CISA-KEV", t9901.RelationshipCount, t9901.PrimarySource)
		}

		// T9902: EPSS percentile 91 -> tier >=90 -> +30, no fail bonus (pass).
		t9902, ok := priorityOf(report.PriorityScores, "T9902")
		if !ok {
			t.Fatal("T9902 missing from PriorityScores")
		}
		if t9902.KEV {
			t.Errorf("T9902 KEV = true, want false (only an EPSS relationship was seeded)")
		}
		// percentile round-trips through a Postgres `real` (float32) column, so
		// compare with a tolerance rather than exact equality.
		if d := t9902.EPSSPercentile - 91; d > 0.01 || d < -0.01 {
			t.Errorf("T9902 EPSSPercentile = %.4f, want ~91", t9902.EPSSPercentile)
		}
		if t9902.PriorityScore != 30 {
			t.Errorf("T9902 PriorityScore = %d, want 30 (EPSS tier 90 -> +30)", t9902.PriorityScore)
		}

		// Sort: higher score (T9901=50) must rank ahead of T9902=30.
		if report.PriorityScores[0].TechniqueID != "T9901" {
			t.Errorf("PriorityScores[0] = %s, want T9901 first (higher score)", report.PriorityScores[0].TechniqueID)
		}
	})
}

// TestPopulatePriorityScores_NoSignalPassIsOmitted proves a technique with no
// KEV/EPSS/actor signal that passed is dropped as "no actionable output",
// while the same no-signal technique with a fail verdict is kept.
func TestPopulatePriorityScores_NoSignalPassIsOmitted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		priorityBySeedTechnique(t, pool, "T9903", "Fictional System Discovery", "discovery")
		priorityBySeedTechnique(t, pool, "T9904", "Fictional Process Discovery", "discovery")

		e := NewEngine(pool)
		report := &FullReport{TechniqueMatrix: []TechniqueRow{
			{TechniqueID: "T9903", TechniqueName: "Fictional System Discovery", Tactic: "discovery", ExecVerdict: "pass"},
			{TechniqueID: "T9904", TechniqueName: "Fictional Process Discovery", Tactic: "discovery", ExecVerdict: "fail"},
		}}
		e.populatePriorityScores(context.Background(), report)

		if _, ok := priorityOf(report.PriorityScores, "T9903"); ok {
			t.Error("T9903 (no signal, passed) should have been omitted")
		}
		t9904, ok := priorityOf(report.PriorityScores, "T9904")
		if !ok {
			t.Fatal("T9904 (no signal, failed) should still appear via the fail bonus")
		}
		if t9904.PriorityScore != 10 {
			t.Errorf("T9904 PriorityScore = %d, want 10 (fail bonus only)", t9904.PriorityScore)
		}
	})
}

// TestPopulatePriorityScores_ErrorAndSkippedVerdictsExcluded proves
// error/skipped-verdict techniques never enter PriorityScores, even when a
// KEV relationship would otherwise give them a large score.
func TestPopulatePriorityScores_ErrorAndSkippedVerdictsExcluded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		priorityBySeedTechnique(t, pool, "T9905", "Fictional Exploit Public-Facing App", "initial-access")
		seedKEVRelationship(t, pool, "T9905", "CVE-2024-0003", "High", "Active")
		priorityBySeedTechnique(t, pool, "T9906", "Fictional Exploitation of Remote Services", "lateral-movement")
		seedKEVRelationship(t, pool, "T9906", "CVE-2024-0004", "High", "Active")

		e := NewEngine(pool)
		report := &FullReport{TechniqueMatrix: []TechniqueRow{
			{TechniqueID: "T9905", TechniqueName: "Fictional Exploit Public-Facing App", Tactic: "initial-access", ExecVerdict: "error"},
			{TechniqueID: "T9906", TechniqueName: "Fictional Exploitation of Remote Services", Tactic: "lateral-movement", ExecVerdict: "skipped"},
		}}
		e.populatePriorityScores(context.Background(), report)

		if len(report.PriorityScores) != 0 {
			t.Errorf("PriorityScores = %+v, want empty — error/skipped verdicts must never be scored", report.PriorityScores)
		}
	})
}

// TestPopulatePriorityScores_LowConfidenceRelationshipIgnored proves a
// Low-confidence relationship never contributes to KEV/EPSS/relationship-count
// signal — matching the doc comment ("Only Active relationships with
// High/Medium effective confidence contribute").
func TestPopulatePriorityScores_LowConfidenceRelationshipIgnored(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		priorityBySeedTechnique(t, pool, "T9907", "Fictional Phishing", "initial-access")
		seedKEVRelationship(t, pool, "T9907", "CVE-2024-0005", "Low", "Active")

		e := NewEngine(pool)
		report := &FullReport{TechniqueMatrix: []TechniqueRow{
			{TechniqueID: "T9907", TechniqueName: "Fictional Phishing", Tactic: "initial-access", ExecVerdict: "pass"},
		}}
		e.populatePriorityScores(context.Background(), report)

		if _, ok := priorityOf(report.PriorityScores, "T9907"); ok {
			t.Error("T9907 should be omitted — its only relationship is Low confidence and it passed, so no signal, no fail bonus")
		}
	})
}

// TestPopulatePriorityScores_DeprecatedRelationshipIgnored proves a
// non-Active relationship (status != 'Active') never contributes, matching
// the same doc comment as the confidence check above.
func TestPopulatePriorityScores_DeprecatedRelationshipIgnored(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		priorityBySeedTechnique(t, pool, "T9908", "Fictional Data Encrypted for Impact", "impact")
		seedKEVRelationship(t, pool, "T9908", "CVE-2024-0006", "High", "Deprecated")

		e := NewEngine(pool)
		report := &FullReport{TechniqueMatrix: []TechniqueRow{
			{TechniqueID: "T9908", TechniqueName: "Fictional Data Encrypted for Impact", Tactic: "impact", ExecVerdict: "pass"},
		}}
		e.populatePriorityScores(context.Background(), report)

		if _, ok := priorityOf(report.PriorityScores, "T9908"); ok {
			t.Error("T9908 should be omitted — its only relationship is Deprecated, not Active")
		}
	})
}
