package connector

import (
	"context"
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
