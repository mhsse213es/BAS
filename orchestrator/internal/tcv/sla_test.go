package tcv

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func wantSec(t *testing.T, got map[Stage]*int64, stage Stage, want int64) {
	t.Helper()
	if got[stage] == nil {
		t.Fatalf("%s = open(nil), want %d", stage, want)
	}
	if *got[stage] != want {
		t.Fatalf("%s = %d, want %d", stage, *got[stage], want)
	}
}

// Pure stage-delta logic (spec §9): a partial event list measures only the
// stages whose bounding events are present; a full list measures all four.
func TestStageSeconds_OpenAndMeasured(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	partial := []Event{
		{Type: EventThreatObserved, EventTime: base},
		{Type: EventThreatEligible, EventTime: base.Add(60 * time.Second)},
	}
	got := stageSeconds(partial)
	wantSec(t, got, StageQueue, 60)
	if got[StageGeneration] != nil {
		t.Fatalf("generation = %d, want open(nil)", *got[StageGeneration])
	}
	if got[StageValidation] != nil {
		t.Fatalf("validation = %d, want open(nil)", *got[StageValidation])
	}
	if got[StageEndToEnd] != nil {
		t.Fatalf("end-to-end = %d, want open(nil)", *got[StageEndToEnd])
	}

	full := []Event{
		{Type: EventThreatObserved, EventTime: base},
		{Type: EventThreatEligible, EventTime: base.Add(60 * time.Second)},
		{Type: EventContentCreated, EventTime: base.Add(200 * time.Second)},
		{Type: EventValidatedCoverage, EventTime: base.Add(500 * time.Second)},
	}
	g := stageSeconds(full)
	wantSec(t, g, StageQueue, 60)
	wantSec(t, g, StageGeneration, 140)
	wantSec(t, g, StageValidation, 300)
	wantSec(t, g, StageEndToEnd, 500)
}

// ── DB-backed SLA projection tests ───────────────────────────────────────

var slaSince = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func recEvent(t *testing.T, pool *pgxpool.Pool, e Event) {
	t.Helper()
	if err := RecordPipelineEvent(context.Background(), pool, e); err != nil {
		t.Fatalf("seed event %s: %v", e.Type, err)
	}
}

// seedThreatClock seeds the threat-level observed (+optional eligible) events.
func seedThreatClock(t *testing.T, pool *pgxpool.Pool, threatID, source string, observed time.Time, eligible *time.Time) {
	t.Helper()
	recEvent(t, pool, Event{Type: EventThreatObserved, ThreatID: threatID, EventTime: observed,
		SourceTable: "source_observations", SourcePK: threatID, Payload: map[string]any{"source": source}})
	if eligible != nil {
		recEvent(t, pool, Event{Type: EventThreatEligible, ThreatID: threatID, EventTime: *eligible,
			SourceTable: "content_generation_cycle", SourcePK: threatID})
	}
}

// seedLeg links version→threat and seeds the content-level events for one
// (threat, kind) leg. created/validated nil = that milestone not reached;
// failed=true seeds a FAIL validation_resulted.
func seedLeg(t *testing.T, pool *pgxpool.Pool, threatID, kind, vid string, created, validated *time.Time, failed bool) {
	t.Helper()
	prov := "admin"
	if kind == "generated_for" {
		prov = "generator"
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO content_version_threats (content_version_id, threat_id, relationship_kind, provenance_type, provenance_ref)
		 VALUES ($1,$2,$3,$4,'r') ON CONFLICT DO NOTHING`, vid, threatID, kind, prov); err != nil {
		t.Fatalf("seed leg link: %v", err)
	}
	if created != nil {
		recEvent(t, pool, Event{Type: EventContentCreated, ThreatID: threatID, ContentVersionID: vid,
			GenerationAttemptID: "cga-" + vid, EventTime: *created,
			SourceTable: "content_generation_attempts", SourcePK: "cga-" + vid,
			Payload: map[string]any{"outcome": "created"}})
	}
	if failed {
		recEvent(t, pool, Event{Type: EventValidationResulted, ContentVersionID: vid, ValidationRunID: "run-" + vid,
			EventTime: created.Add(time.Minute), SourceTable: "content_validations", SourcePK: "run-" + vid,
			Payload: map[string]any{"outcome": "FAIL"}})
	}
	if validated != nil {
		recEvent(t, pool, Event{Type: EventValidatedCoverage, ContentVersionID: vid, EventTime: *validated,
			SourceTable: "content_version_events", SourcePK: "cve-" + vid,
			Payload: map[string]any{"to_lifecycle": "VALIDATED"}})
	}
}

func tp(base time.Time, sec int) *time.Time {
	u := base.Add(time.Duration(sec) * time.Second)
	return &u
}

func findSeg(segs []SLASegment, ct, cohort string) *SLASegment {
	for i := range segs {
		if segs[i].ContentType == ct && segs[i].Cohort == cohort {
			return &segs[i]
		}
	}
	return nil
}

// Acceptance 14: stages have independent populations. A queue-only leg counts
// in the queue stage and is absent from generation/validation.
func TestSLA_IndependentStagePopulations(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		base := slaSince.Add(time.Hour)
		// Leg A: full validated leg.
		tA := seedThreat(t, "APT-indepA")
		vA := seedContentVersion(t, "cv-indepA")
		seedThreatClock(t, pool, tA, "misp", base, tp(base, 60))
		seedLeg(t, pool, tA, "emulates", vA, tp(base, 200), tp(base, 500), false)
		// Leg B: queue-only (observed+eligible, no content).
		tB := seedThreat(t, "APT-indepB")
		seedThreatClock(t, pool, tB, "misp", base, tp(base, 90))

		store := NewStore(pool)
		q, err := store.SLA(ctx, StageQueue, slaSince)
		if err != nil {
			t.Fatal(err)
		}
		// Queue stage includes both legs: A validated, B open.
		if s := findSeg(q.Segments, "emulates", "validated"); s == nil || s.N != 1 {
			t.Fatalf("queue validated emulates N: %+v", q.Segments)
		}
		if s := findSeg(q.Segments, "", "open"); s == nil || s.N != 1 {
			t.Fatalf("queue open (queue-only leg) N: %+v", q.Segments)
		}

		g, err := store.SLA(ctx, StageGeneration, slaSince)
		if err != nil {
			t.Fatal(err)
		}
		// Generation population excludes the queue-only leg entirely.
		if s := findSeg(g.Segments, "", "open"); s != nil {
			t.Fatalf("queue-only leg must be absent from generation, got %+v", s)
		}
		total := 0
		for _, s := range g.Segments {
			total += s.N
		}
		if total != 1 {
			t.Fatalf("generation total N = %d, want 1 (only leg A)", total)
		}
	})
}

// Acceptance 15: percentiles over the validated cohort only; failed/open are
// counts; open cohort count + oldest age reported.
func TestSLA_ValidatedCohortOnly(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		base := slaSince.Add(time.Hour)
		// All three legs reach the generation stage (eligible + created).
		tv := seedThreat(t, "APT-vco-v")
		vv := seedContentVersion(t, "cv-vco-v")
		seedThreatClock(t, pool, tv, "misp", base, tp(base, 10))
		seedLeg(t, pool, tv, "emulates", vv, tp(base, 100), tp(base, 300), false)

		tf := seedThreat(t, "APT-vco-f")
		vf := seedContentVersion(t, "cv-vco-f")
		seedThreatClock(t, pool, tf, "misp", base, tp(base, 10))
		seedLeg(t, pool, tf, "emulates", vf, tp(base, 100), nil, true) // failed, no coverage

		to := seedThreat(t, "APT-vco-o")
		vo := seedContentVersion(t, "cv-vco-o")
		seedThreatClock(t, pool, to, "misp", base, tp(base, 10))
		seedLeg(t, pool, to, "emulates", vo, tp(base, 100), nil, false) // open, no verdict

		g, err := NewStore(pool).SLA(ctx, StageGeneration, slaSince)
		if err != nil {
			t.Fatal(err)
		}
		v := findSeg(g.Segments, "emulates", "validated")
		if v == nil || v.N != 1 || v.P50Seconds == nil {
			t.Fatalf("validated generation segment: %+v", g.Segments)
		}
		if f := findSeg(g.Segments, "emulates", "failed"); f == nil || f.N != 1 || f.P50Seconds != nil {
			t.Fatalf("failed segment: %+v", g.Segments)
		}
		if o := findSeg(g.Segments, "emulates", "open"); o == nil || o.N != 1 {
			t.Fatalf("open segment: %+v", g.Segments)
		}
		if g.OpenCount != 1 || g.OldestOpenSeconds == nil {
			t.Fatalf("open cohort: count=%d oldest=%v", g.OpenCount, g.OldestOpenSeconds)
		}
	})
}

// Acceptance 9: correct P50/P95 on a seeded distribution; an empty stage
// reports no segments without error.
func TestSLA_PercentilesAndEmptySegment(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		base := slaSince.Add(time.Hour)
		// Four validated legs with queue durations 10,20,30,40s.
		for i, q := range []int{10, 20, 30, 40} {
			id := string(rune('a' + i))
			th := seedThreat(t, "APT-pct-"+id)
			v := seedContentVersion(t, "cv-pct-"+id)
			seedThreatClock(t, pool, th, "misp", base, tp(base, q))
			seedLeg(t, pool, th, "emulates", v, tp(base, q+100), tp(base, q+200), false)
		}
		rep, err := NewStore(pool).SLA(ctx, StageQueue, slaSince)
		if err != nil {
			t.Fatal(err)
		}
		v := findSeg(rep.Segments, "emulates", "validated")
		if v == nil || v.N != 4 || v.P50Seconds == nil || v.P95Seconds == nil {
			t.Fatalf("queue validated segment: %+v", rep.Segments)
		}
		if *v.P50Seconds != 25 {
			t.Fatalf("P50 = %v, want 25", *v.P50Seconds)
		}
		if *v.P95Seconds != 38.5 {
			t.Fatalf("P95 = %v, want 38.5", *v.P95Seconds)
		}

		// Empty: validation stage has no legs (none validated via EXECUTION path here
		// -> validated_coverage present but validation stage needs created->validated,
		// which these have; use a window far in the future for emptiness).
		empty, err := NewStore(pool).SLA(ctx, StageQueue, base.Add(1000*time.Second))
		if err != nil {
			t.Fatalf("empty window errored: %v", err)
		}
		if len(empty.Segments) != 0 {
			t.Fatalf("empty window segments = %+v, want none", empty.Segments)
		}
	})
}

// Acceptance 10: Bottleneck = the stage with the largest validated P95.
func TestSLA_BottleneckNamesLargestP95(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		base := slaSince.Add(time.Hour)
		// Generation dwarfs the other stages.
		th := seedThreat(t, "APT-bottle")
		v := seedContentVersion(t, "cv-bottle")
		seedThreatClock(t, pool, th, "misp", base, tp(base, 5)) // queue 5s
		// eligible@5 -> created@9005 (generation 9000s) -> validated@9010 (validation 5s)
		seedLeg(t, pool, th, "emulates", v, tp(base, 9005), tp(base, 9010), false)

		rep, err := NewStore(pool).SLA(ctx, StageQueue, slaSince)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Bottleneck != StageGeneration {
			t.Fatalf("Bottleneck = %s, want generation", rep.Bottleneck)
		}
	})
}

// Acceptance 11: a leg with threat_observed but no threat_eligible is excluded
// from P50/P95 and sets IncompleteWindow.
func TestSLA_IncompleteWindowExcludedAndFlagged(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		base := slaSince.Add(time.Hour)
		// Complete validated leg.
		tc := seedThreat(t, "APT-complete")
		vc := seedContentVersion(t, "cv-complete")
		seedThreatClock(t, pool, tc, "misp", base, tp(base, 30))
		seedLeg(t, pool, tc, "emulates", vc, tp(base, 100), tp(base, 400), false)
		// Incomplete leg: observed + created + validated but NO eligible.
		ti := seedThreat(t, "APT-incomplete")
		vi := seedContentVersion(t, "cv-incomplete")
		seedThreatClock(t, pool, ti, "misp", base, nil) // observed only
		seedLeg(t, pool, ti, "emulates", vi, tp(base, 100), tp(base, 400), false)

		rep, err := NewStore(pool).SLA(ctx, StageEndToEnd, slaSince)
		if err != nil {
			t.Fatal(err)
		}
		if !rep.IncompleteWindow {
			t.Fatalf("IncompleteWindow = false, want true")
		}
		v := findSeg(rep.Segments, "emulates", "validated")
		if v == nil || v.N != 1 {
			t.Fatalf("end-to-end validated N = %+v, want 1 (incomplete leg excluded)", rep.Segments)
		}
	})
}

// Review Focus: a threat with both emulates and generated_for legs yields two
// independent rows, never merged.
func TestSLA_TwoLegThreatNotMerged(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		base := slaSince.Add(time.Hour)
		th := seedThreat(t, "APT-twoleg")
		ve := seedContentVersion(t, "cv-twoleg-e")
		vg := seedContentVersion(t, "cv-twoleg-g")
		seedThreatClock(t, pool, th, "misp", base, tp(base, 20))
		seedLeg(t, pool, th, "emulates", ve, tp(base, 100), tp(base, 300), false)
		seedLeg(t, pool, th, "generated_for", vg, tp(base, 150), tp(base, 600), false)

		rep, err := NewStore(pool).SLA(ctx, StageEndToEnd, slaSince)
		if err != nil {
			t.Fatal(err)
		}
		e := findSeg(rep.Segments, "emulates", "validated")
		g := findSeg(rep.Segments, "generated_for", "validated")
		if e == nil || g == nil || e.N != 1 || g.N != 1 {
			t.Fatalf("two legs not independent: %+v", rep.Segments)
		}
	})
}

// Acceptance 16: a leg demoted/retired after validated_coverage keeps its
// end-to-end measurement (coverage is monotone for velocity).
func TestSLA_MonotoneAfterDemotion(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		base := slaSince.Add(time.Hour)
		th := seedThreat(t, "APT-monotone")
		v := seedContentVersion(t, "cv-monotone")
		seedThreatClock(t, pool, th, "misp", base, tp(base, 40))
		seedLeg(t, pool, th, "emulates", v, tp(base, 100), tp(base, 500), false)
		// A later retirement must not un-measure coverage.
		recEvent(t, pool, Event{Type: EventRetired, ContentVersionID: v, EventTime: base.Add(900 * time.Second),
			SourceTable: "content_version_events", SourcePK: "cve-retire-" + v,
			Payload: map[string]any{"to_lifecycle": "RETIRED"}})

		rep, err := NewStore(pool).SLA(ctx, StageEndToEnd, slaSince)
		if err != nil {
			t.Fatal(err)
		}
		e := findSeg(rep.Segments, "emulates", "validated")
		if e == nil || e.N != 1 || e.P50Seconds == nil || *e.P50Seconds != 500 {
			t.Fatalf("monotone end-to-end: %+v", rep.Segments)
		}
	})
}
