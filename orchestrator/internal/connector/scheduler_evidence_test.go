package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/evidence"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/threatidentity"
)

// stubEvidenceSource is a minimal Source + CompletenessSource + EvidenceSource
// test double standing in for MISP/OpenCTI without a network call.
type stubEvidenceSource struct {
	name   string
	actors []ThreatActor
	claims []evidence.RawClaim
}

func (s *stubEvidenceSource) Name() string                      { return s.name }
func (s *stubEvidenceSource) Fetch() ([]ThreatActor, error)     { return s.actors, nil }
func (s *stubEvidenceSource) Completeness() evidence.SyncReport { return evidence.SyncReport{Completeness: evidence.Complete} }
func (s *stubEvidenceSource) RawClaims() []evidence.RawClaim    { return s.claims }

// scenarioEngineForTest builds a *scenario.Engine the same way the existing
// sync()-exercising tests in scheduler_test.go do.
func scenarioEngineForTest(t *testing.T) *scenario.Engine {
	t.Helper()
	return scenario.NewEngine(t.TempDir())
}

func TestScheduler_Sync_RecordsEvidenceAndProjectsActiveTechniques(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		src := &stubEvidenceSource{
			name: "misp",
			actors: []ThreatActor{
				{Name: "APT-sched-evidence", Source: "misp", SourceID: "evt-1",
					Techniques: []TechniqueRef{{ID: "T1059"}, {ID: "T1055"}}},
			},
			claims: []evidence.RawClaim{
				{ActorName: "APT-sched-evidence", TechniqueID: "T1059", ExternalID: "evt-1", ObservedAt: time.Now(), RawConfidence: "high"},
				{ActorName: "APT-sched-evidence", TechniqueID: "T1055", ExternalID: "evt-1", ObservedAt: time.Now(), RawConfidence: "high"},
			},
		}
		s := &Scheduler{pool: pool, sources: []Source{src}, generator: NewGenerator(t.TempDir(), nil, nil, nil), engine: scenarioEngineForTest(t)}
		s.WithIdentityStore(threatidentity.NewStore(pool))
		s.WithEvidenceStore(evidence.NewStore(pool))

		s.sync()

		var threatID string
		if err := pool.QueryRow(ctx, `SELECT t.id FROM threats t JOIN threat_actor_profiles p ON p.id = t.actor_id
			WHERE p.name = 'APT-sched-evidence'`).Scan(&threatID); err != nil {
			t.Fatalf("resolved threat not found: %v", err)
		}

		var activeCount int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM threat_techniques WHERE threat_id = $1 AND status = 'active'`, threatID).Scan(&activeCount); err != nil {
			t.Fatal(err)
		}
		if activeCount != 2 {
			t.Fatalf("active threat_techniques rows = %d, want 2 (T1059, T1055)", activeCount)
		}

		var claimCount int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM technique_claims WHERE threat_id = $1`, threatID).Scan(&claimCount); err != nil {
			t.Fatal(err)
		}
		if claimCount != 2 {
			t.Fatalf("technique_claims rows = %d, want 2", claimCount)
		}
	})
}

// TestScheduler_Sync_SubThresholdActorStillGetsClaimRecorded pins the
// finding from the 2B final review: MISP's Fetch() drops an actor with
// fewer than 2 techniques from its OWN returned actor list (misp.go's
// generation-threshold filter), so that actor never enters the merged,
// identity-resolved roster sync() builds threatByName from -- its captured
// RawClaims() then has no ThreatID to resolve against and is silently
// dropped. The generation-threshold filter must live only in
// Generator.Write() (Task 13's ActiveTechniques check); Fetch() itself must
// return every actor with at least one technique.
func TestScheduler_Sync_SubThresholdActorStillGetsClaimRecorded(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/events/index":
				json.NewEncoder(w).Encode([]mispEventIndex{
					{ID: "1", Info: "solo event", Tag: []mispTag{{Name: "mitre-attack-pattern"}}},
				})
			case "/events/1":
				var detail mispEventDetail
				detail.Event.Tag = []mispTag{{Name: `misp-galaxy:threat-actor="Solo Sched Actor"`}}
				detail.Event.GalaxyCluster = []mispGalaxy{{
					Type: "mitre-attack-pattern",
					Meta: struct {
						ExternalID []string `json:"external_id"`
						KillChain  []string `json:"kill_chain"`
					}{ExternalID: []string{"T1059"}},
				}}
				json.NewEncoder(w).Encode(detail)
			default:
				t.Fatalf("unexpected request path: %s", r.URL.Path)
			}
		}))
		defer server.Close()

		src := NewMISPClient(server.URL, "test-key", nil, nil, false)
		s := &Scheduler{pool: pool, sources: []Source{src}, generator: NewGenerator(t.TempDir(), nil, nil, nil), engine: scenarioEngineForTest(t)}
		s.WithIdentityStore(threatidentity.NewStore(pool))
		s.WithEvidenceStore(evidence.NewStore(pool))

		s.sync()

		var threatID string
		if err := pool.QueryRow(ctx, `SELECT t.id FROM threats t JOIN threat_actor_profiles p ON p.id = t.actor_id
			WHERE p.name = 'Solo Sched Actor'`).Scan(&threatID); err != nil {
			t.Fatalf("resolved threat not found for sub-threshold actor: %v", err)
		}

		var claimCount int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM technique_claims WHERE threat_id = $1 AND technique_id = 'T1059'`, threatID).Scan(&claimCount); err != nil {
			t.Fatal(err)
		}
		if claimCount != 1 {
			t.Fatalf("technique_claims rows for the sub-threshold actor's single technique = %d, want 1 (evidence must survive even though generation excludes it)", claimCount)
		}
	})
}

// TestScheduler_Sync_AuthoritativeSyncRetractsAbsentTechnique pins the
// second finding from the 2B final review: nothing in the live scheduler
// ever emitted a ClaimRetracted. A complete snapshot sync that no longer
// claims a previously-claimed technique must retract it (spec §6.1).
func TestScheduler_Sync_AuthoritativeSyncRetractsAbsentTechnique(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		observedAt := time.Now()
		src := &stubEvidenceSource{
			name: "misp",
			actors: []ThreatActor{
				{Name: "APT-retraction-sched", Source: "misp", SourceID: "evt-1",
					Techniques: []TechniqueRef{{ID: "T1059"}, {ID: "T1055"}}},
			},
			claims: []evidence.RawClaim{
				{ActorName: "APT-retraction-sched", TechniqueID: "T1059", ExternalID: "evt-1", ObservedAt: observedAt, RawConfidence: "high"},
				{ActorName: "APT-retraction-sched", TechniqueID: "T1055", ExternalID: "evt-1", ObservedAt: observedAt, RawConfidence: "high"},
			},
		}
		s := &Scheduler{pool: pool, sources: []Source{src}, generator: NewGenerator(t.TempDir(), nil, nil, nil), engine: scenarioEngineForTest(t)}
		s.WithIdentityStore(threatidentity.NewStore(pool))
		s.WithEvidenceStore(evidence.NewStore(pool))

		s.sync()

		var threatID string
		if err := pool.QueryRow(ctx, `SELECT t.id FROM threats t JOIN threat_actor_profiles p ON p.id = t.actor_id
			WHERE p.name = 'APT-retraction-sched'`).Scan(&threatID); err != nil {
			t.Fatalf("resolved threat not found: %v", err)
		}

		// A second, later, complete snapshot sync no longer sees T1055.
		src.actors = []ThreatActor{
			{Name: "APT-retraction-sched", Source: "misp", SourceID: "evt-2",
				Techniques: []TechniqueRef{{ID: "T1059"}}},
		}
		src.claims = []evidence.RawClaim{
			{ActorName: "APT-retraction-sched", TechniqueID: "T1059", ExternalID: "evt-2", ObservedAt: observedAt.Add(time.Hour), RawConfidence: "high"},
		}
		s.sync()

		var retractionCount int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM technique_claims WHERE threat_id = $1 AND technique_id = 'T1055' AND kind = 'retraction'`,
			threatID).Scan(&retractionCount); err != nil {
			t.Fatal(err)
		}
		if retractionCount != 1 {
			t.Fatalf("retraction rows for T1055 = %d, want 1 (complete snapshot no longer claims it)", retractionCount)
		}

		var status string
		if err := pool.QueryRow(ctx,
			`SELECT status FROM threat_techniques WHERE threat_id = $1 AND technique_id = 'T1055'`, threatID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != "retracted" {
			t.Fatalf("T1055 status = %q, want retracted", status)
		}
	})
}

// TestScheduler_Sync_StartsThreatAndIntelligenceClocksOnTrustedClaim closes
// spec §10.2: resolving a trusted claim through the live scheduler path
// must start both the threat clock (at the claim's observed_at) and the
// intelligence clock (at the sync's completed_at).
func TestScheduler_Sync_StartsThreatAndIntelligenceClocksOnTrustedClaim(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		observedAt := time.Now().Add(-6 * time.Hour)
		src := &stubEvidenceSource{
			name: "misp",
			actors: []ThreatActor{
				{Name: "APT-clock-sched", Source: "misp", SourceID: "evt-1",
					Techniques: []TechniqueRef{{ID: "T1059"}, {ID: "T1055"}}},
			},
			claims: []evidence.RawClaim{
				{ActorName: "APT-clock-sched", TechniqueID: "T1059", ExternalID: "evt-1", ObservedAt: observedAt, RawConfidence: "high"},
			},
		}
		s := &Scheduler{pool: pool, sources: []Source{src}, generator: NewGenerator(t.TempDir(), nil, nil, nil), engine: scenarioEngineForTest(t)}
		s.WithIdentityStore(threatidentity.NewStore(pool))
		s.WithEvidenceStore(evidence.NewStore(pool))

		s.sync()

		var threatID string
		if err := pool.QueryRow(ctx, `SELECT t.id FROM threats t JOIN threat_actor_profiles p ON p.id = t.actor_id
			WHERE p.name = 'APT-clock-sched'`).Scan(&threatID); err != nil {
			t.Fatalf("resolved threat not found: %v", err)
		}

		var threatClockCount, intelClockCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM threat_clock_starts WHERE threat_id = $1 AND clock = 'threat'`, threatID).Scan(&threatClockCount); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM threat_clock_starts WHERE threat_id = $1 AND clock = 'intelligence'`, threatID).Scan(&intelClockCount); err != nil {
			t.Fatal(err)
		}
		if threatClockCount != 1 || intelClockCount != 1 {
			t.Fatalf("threat clock rows = %d, intelligence clock rows = %d, want 1 each", threatClockCount, intelClockCount)
		}
	})
}
