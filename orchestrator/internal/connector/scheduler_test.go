package connector

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
)

type fakeSource struct {
	name   string
	actors []ThreatActor
	err    error
	stats  SourceStat
}

func (f fakeSource) Name() string                  { return f.name }
func (f fakeSource) Fetch() ([]ThreatActor, error) { return f.actors, f.err }
func (f fakeSource) Stats() SourceStat             { return f.stats }

func TestNewScheduler_StatusFlags(t *testing.T) {
	s := NewScheduler([]Source{
		fakeSource{name: "misp"},
		fakeSource{name: "bundle"},
	}, NewGenerator(t.TempDir(), nil, nil), nil, 24, sharedDB.Pool)

	st := s.Status()
	if !st.MISPEnabled || !st.BundleEnabled {
		t.Fatalf("expected misp+bundle enabled, got %+v", st)
	}
	if st.OpenCTIEnabled {
		t.Fatal("OpenCTI should be disabled")
	}
	if st.LastSyncStatus != "never" {
		t.Fatalf("status = %q, want never", st.LastSyncStatus)
	}
}

func TestScheduler_Sync_PopulatesBySourcePerSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	mispStat := SourceStat{Name: "misp", RawCount: 5, ActorCount: 2, FetchedAt: time.Now()}
	s := NewScheduler([]Source{
		fakeSource{
			name:   "misp",
			actors: []ThreatActor{{Name: "APT36", Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}}}},
			stats:  mispStat,
		},
		fakeSource{
			name: "opencti",
			err:  errors.New("opencti unreachable"),
			stats: SourceStat{Name: "opencti", Error: "opencti unreachable", FetchedAt: time.Now()},
		},
	}, NewGenerator(t.TempDir(), nil, nil), scenario.NewEngine(t.TempDir()), 24, sharedDB.Pool)

	s.sync()

	st := s.Status()
	if len(st.BySource) != 2 {
		t.Fatalf("BySource = %+v, want 2 entries", st.BySource)
	}
	misp, ok := st.BySource["misp"]
	if !ok || misp.RawCount != 5 || misp.ActorCount != 2 || misp.Error != "" {
		t.Fatalf("BySource[misp] = %+v, want RawCount=5 ActorCount=2 Error=\"\"", misp)
	}
	opencti, ok := st.BySource["opencti"]
	if !ok || opencti.Error != "opencti unreachable" {
		t.Fatalf("BySource[opencti] = %+v, want Error=\"opencti unreachable\"", opencti)
	}
}

func TestMergeActors_UnionsTechniques(t *testing.T) {
	// Layering: same actor from the bundle floor and a live overlay → the
	// techniques are unioned, which is what makes bundle+live compose for free.
	merged := MergeActors([]ThreatActor{
		{Name: "APT36", Source: "bundle", Techniques: []TechniqueRef{{ID: "T1059.001"}}},
		{Name: "APT36", Source: "misp", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
	})
	if len(merged) != 1 {
		t.Fatalf("want 1 merged actor, got %d", len(merged))
	}
	if len(merged[0].Techniques) != 2 {
		t.Fatalf("want 2 unioned techniques, got %d: %+v", len(merged[0].Techniques), merged[0].Techniques)
	}
}

func TestScheduler_SyncUpsertsActorProfiles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := NewScheduler([]Source{
			fakeSource{name: "bundle", actors: []ThreatActor{{
				Name:       "APT36",
				Aliases:    []string{"Transparent Tribe"},
				Sectors:    []string{"government"},
				Regions:    []string{"south-asia"},
				Source:     "bundle",
				Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}},
			}}},
		}, NewGenerator(t.TempDir(), nil, nil), scenario.NewEngine(t.TempDir()), 24, pool)

		s.sync()

		var aliases, sectors, regions []string
		err := pool.QueryRow(t.Context(),
			`SELECT aliases, sectors, regions FROM threat_actor_profiles WHERE name = 'APT36'`,
		).Scan(&aliases, &sectors, &regions)
		if err != nil {
			t.Fatalf("expected APT36 profile to be persisted: %v", err)
		}
		if len(aliases) != 1 || aliases[0] != "Transparent Tribe" {
			t.Errorf("aliases = %v, want [Transparent Tribe]", aliases)
		}
		if len(sectors) != 1 || sectors[0] != "government" {
			t.Errorf("sectors = %v, want [government]", sectors)
		}
		if len(regions) != 1 || regions[0] != "south-asia" {
			t.Errorf("regions = %v, want [south-asia]", regions)
		}
	})
}
