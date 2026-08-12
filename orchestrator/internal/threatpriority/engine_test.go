package threatpriority

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
)

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func TestNewEngine_UsesDefaultFactors(t *testing.T) {
	e := NewEngine(nil, scenario.NewEngine(t.TempDir()), nil, nil)
	if len(e.factors) != 10 {
		t.Fatalf("got %d factors, want 10", len(e.factors))
	}
}

func TestScoreActor_ComputesCompositeFromRealFactors(t *testing.T) {
	// Exercises scoreActor directly with a hand-built sharedIndexes, bypassing
	// the DB (e.pool is nil, and previousScore is nil-pool-safe -- see
	// engine.go). Full ScoreAll/Score DB-backed behavior is covered by
	// history_test.go in Task 8, once threat_priority_history exists.
	e := &Engine{factors: DefaultFactors()}
	shared := &sharedIndexes{
		simulation: map[string]bool{"T1059": true},
		detection:  map[string]bool{"T1059": true},
		purple:     map[string]bool{},
		compliance: map[string]bool{},
	}
	profile := &ActorProfile{Name: "TEST-ACTOR-X", Confidence: "high"}

	// Name won't resolve against attackdata.GroupTechniqueIndex, so
	// scoreActor's own technique resolution yields nil TechniqueIDs --
	// exercise the "no known techniques" path deliberately here, and cover
	// the real-technique path via ScoreAll's DB-backed integration test in
	// Task 8/10 instead (technique resolution depends on real embedded
	// ATT&CK data, not something to fake in a unit test).
	ap, err := e.scoreActor(context.Background(), profile, shared)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ap.Tier == "" {
		t.Fatal("expected a non-empty tier")
	}
	if len(ap.Factors) != 10 {
		t.Fatalf("got %d factor results, want 10", len(ap.Factors))
	}
}

// scoreActor must copy CanonicalGroupID straight through from the profile
// -- no DB involved (mirrors TestScoreActor_ComputesCompositeFromRealFactors's
// pattern of calling scoreActor directly with a hand-built profile).
func TestScoreActor_CopiesCanonicalGroupIDFromProfile(t *testing.T) {
	e := &Engine{factors: DefaultFactors()}
	shared := &sharedIndexes{
		simulation: map[string]bool{}, detection: map[string]bool{},
		purple: map[string]bool{}, compliance: map[string]bool{},
	}
	profile := &ActorProfile{Name: "TEST-ACTOR-CANON", CanonicalGroupID: "G0016"}
	ap, err := e.scoreActor(context.Background(), profile, shared)
	if err != nil {
		t.Fatalf("scoreActor: %v", err)
	}
	if ap.CanonicalGroupID != "G0016" {
		t.Errorf("CanonicalGroupID = %q, want G0016", ap.CanonicalGroupID)
	}
}

func TestLoadProfile_ReadsCanonicalGroupID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO threat_actor_profiles (name, canonical_group_id) VALUES ('TP-CANON-TEST', 'G0016')
			ON CONFLICT (name) DO UPDATE SET canonical_group_id = EXCLUDED.canonical_group_id`)
		e := &Engine{pool: pool}
		p, err := e.loadProfile(context.Background(), "TP-CANON-TEST")
		if err != nil {
			t.Fatalf("loadProfile: %v", err)
		}
		if p == nil {
			t.Fatal("expected a profile row")
		}
		if p.CanonicalGroupID != "G0016" {
			t.Errorf("CanonicalGroupID = %q, want G0016", p.CanonicalGroupID)
		}
	})
}

func TestLoadPreventionVerdicts_LatestWinsAndCarriesTimestamp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		older := time.Now().UTC().Add(-48 * time.Hour)
		newer := time.Now().UTC().Add(-1 * time.Hour)
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('vt-a1', 'VT-HOST')`)
		mustExec(t, pool, `INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('vt-run-old', 'vt-scn', 'VT Old', 'vt-a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1059"},"result":"fail","executedAt":"`+older.Format(time.RFC3339)+`"}]`)
		mustExec(t, pool, `INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('vt-run-new', 'vt-scn', 'VT New', 'vt-a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1059"},"result":"pass","executedAt":"`+newer.Format(time.RFC3339)+`"}]`)

		verdicts, err := LoadPreventionVerdicts(ctx, pool)
		if err != nil {
			t.Fatalf("LoadPreventionVerdicts: %v", err)
		}
		v, ok := verdicts["T1059"]
		if !ok {
			t.Fatal("expected T1059 in the verdict map")
		}
		if v.Verdict != "pass" {
			t.Errorf("Verdict = %q, want %q (the later run)", v.Verdict, "pass")
		}
		if v.At.Sub(newer).Abs() > time.Second {
			t.Errorf("At = %v, want ~%v (the later run's executedAt)", v.At, newer)
		}
	})
}

// TestScoreActor_MITREMatchWinsOverConnectorTechniques proves MITRE stays
// primary: even when the profile also carries connector-sourced
// techniques, a real MITRE-name match must win, not merge or get
// overridden.
func TestScoreActor_MITREMatchWinsOverConnectorTechniques(t *testing.T) {
	e := &Engine{factors: DefaultFactors()}
	shared := &sharedIndexes{
		simulation: map[string]bool{}, detection: map[string]bool{},
		purple: map[string]bool{}, compliance: map[string]bool{},
	}
	// "Wizard Spider" is an established real MITRE group fixture already
	// relied on elsewhere in this codebase (attackdata_test.go,
	// otx_test.go). Give the profile a DIFFERENT connector-sourced
	// technique the MITRE list would never contain, so a test failure here
	// would be obvious (a mixed/merged list, not just a coincidental match).
	profile := &ActorProfile{Name: "Wizard Spider", Techniques: []string{"T9999"}}
	ap, err := e.scoreActor(context.Background(), profile, shared)
	if err != nil {
		t.Fatalf("scoreActor: %v", err)
	}
	if ap.TechniqueSource != "mitre" {
		t.Errorf("TechniqueSource = %q, want mitre", ap.TechniqueSource)
	}
	for _, id := range ap.TechniqueIDs {
		if id == "T9999" {
			t.Fatal("MITRE-authoritative result must not be mixed with connector-sourced techniques")
		}
	}
	if len(ap.TechniqueIDs) == 0 {
		t.Fatal("expected Wizard Spider's real MITRE technique list, got none")
	}
}

// TestScoreActor_FallsBackToConnectorTechniques_NoMITREMatch is the core
// regression guard for this whole fix: an actor MITRE doesn't recognize by
// name must still get scored against whatever real technique evidence a
// connector supplied, instead of silently zero.
func TestScoreActor_FallsBackToConnectorTechniques_NoMITREMatch(t *testing.T) {
	e := &Engine{factors: DefaultFactors()}
	shared := &sharedIndexes{
		simulation: map[string]bool{"T1059.001": true}, detection: map[string]bool{},
		purple: map[string]bool{}, compliance: map[string]bool{},
	}
	profile := &ActorProfile{
		Name:       "TEST-NOT-A-REAL-MITRE-GROUP-NAME-ZZYZX",
		Techniques: []string{"T1059.001", "T1566.001"},
	}
	ap, err := e.scoreActor(context.Background(), profile, shared)
	if err != nil {
		t.Fatalf("scoreActor: %v", err)
	}
	if ap.TechniqueSource != "connector" {
		t.Errorf("TechniqueSource = %q, want connector", ap.TechniqueSource)
	}
	if len(ap.TechniqueIDs) != 2 {
		t.Fatalf("TechniqueIDs = %v, want the 2 connector-sourced techniques", ap.TechniqueIDs)
	}
	if ap.CoverageGapCount != 1 {
		t.Fatalf("CoverageGapCount = %d, want 1 (T1566.001 has no coverage, T1059.001 does)", ap.CoverageGapCount)
	}
}

// TestScoreActor_NoMITREMatchNoConnectorTechniques_EmptyAndUnavailable
// proves the pre-existing "unknown, not none" discipline still holds when
// NEITHER source has anything: an empty TechniqueIDs list, not a fake
// zero-coverage-gap "fully covered" result. Coverage/Validation factors
// already handle this correctly (TestSimulationCoverageFactor_NoTechniques_Unavailable
// and siblings) -- this test guards that this fix doesn't regress it.
func TestScoreActor_NoMITREMatchNoConnectorTechniques_EmptyAndUnavailable(t *testing.T) {
	e := &Engine{factors: DefaultFactors()}
	shared := &sharedIndexes{
		simulation: map[string]bool{}, detection: map[string]bool{},
		purple: map[string]bool{}, compliance: map[string]bool{},
	}
	profile := &ActorProfile{Name: "TEST-NOT-A-REAL-MITRE-GROUP-NAME-ZZYZX-2"}
	ap, err := e.scoreActor(context.Background(), profile, shared)
	if err != nil {
		t.Fatalf("scoreActor: %v", err)
	}
	if ap.TechniqueSource != "" {
		t.Errorf("TechniqueSource = %q, want empty", ap.TechniqueSource)
	}
	if len(ap.TechniqueIDs) != 0 {
		t.Fatalf("TechniqueIDs = %v, want empty", ap.TechniqueIDs)
	}
	if ap.CoverageGapCount != 0 {
		t.Fatalf("CoverageGapCount = %d, want 0 (no techniques to have a gap in, not a false all-covered claim)", ap.CoverageGapCount)
	}
	for _, f := range ap.Factors {
		if f.Name == "Simulation Coverage" && f.Available {
			t.Error("Simulation Coverage must report Available=false with zero known techniques, not a false positive")
		}
	}
}
