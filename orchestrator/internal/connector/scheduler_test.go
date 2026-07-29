package connector

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/intelligence"
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
	}, NewGenerator(t.TempDir(), nil, nil, nil), nil, 24, sharedDB.Pool, nil)

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
	}, NewGenerator(t.TempDir(), nil, nil, nil), scenario.NewEngine(t.TempDir()), 24, sharedDB.Pool, nil)

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

func TestScheduler_Sync_ZeroActorSourceDoesNotDisruptOthers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	otxStat := SourceStat{Name: "otx", RawCount: 47, ActorCount: 0, FetchedAt: time.Now()}
	s := NewScheduler([]Source{
		fakeSource{
			name:   "misp",
			actors: []ThreatActor{{Name: "APT36", Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}}}},
			stats:  SourceStat{Name: "misp", RawCount: 5, ActorCount: 1, FetchedAt: time.Now()},
		},
		fakeSource{
			name:   "otx",
			actors: nil,
			stats:  otxStat,
		},
	}, NewGenerator(t.TempDir(), nil, nil, nil), scenario.NewEngine(t.TempDir()), 24, sharedDB.Pool, nil)

	s.sync()

	st := s.Status()
	if len(st.BySource) != 2 {
		t.Fatalf("BySource = %+v, want 2 entries", st.BySource)
	}
	otx, ok := st.BySource["otx"]
	if !ok || otx.RawCount != 47 || otx.ActorCount != 0 || otx.Error != "" {
		t.Fatalf("BySource[otx] = %+v, want RawCount=47 ActorCount=0 Error=\"\"", otx)
	}
	if st.TotalActors != 1 {
		t.Fatalf("TotalActors = %d, want 1 (otx contributes zero, misp contributes 1)", st.TotalActors)
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
		}, NewGenerator(t.TempDir(), nil, nil, nil), scenario.NewEngine(t.TempDir()), 24, pool, nil)

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

func TestUpsertActorProfiles_PersistsConfidence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		s.upsertActorProfiles([]ThreatActor{{
			Name: "APT-CONFIDENCE-TEST", Confidence: "high",
			Aliases: []string{}, Sectors: []string{}, Regions: []string{},
		}})

		var confidence string
		err := pool.QueryRow(t.Context(),
			`SELECT confidence FROM threat_actor_profiles WHERE name=$1`, "APT-CONFIDENCE-TEST").Scan(&confidence)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if confidence != "high" {
			t.Fatalf("confidence = %q, want %q", confidence, "high")
		}
	})
}

func TestScheduler_Sync_PersistsCampaignsAndMalwareFromIntelligenceSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		index := []mispEventIndex{
			{ID: "sched-1", Info: "Scheduler Wiring Test Event", Timestamp: "1700000000", Tag: []mispTag{{Name: "mitre-attack-pattern"}}},
		}
		server := mispServer(t, index, map[string]mispEventDetail{
			"sched-1": {Event: struct {
				ID            string          `json:"id"`
				Info          string          `json:"info"`
				Timestamp     string          `json:"timestamp"`
				Tag           []mispTag       `json:"Tag"`
				GalaxyCluster []mispGalaxy    `json:"GalaxyCluster"`
				Attribute     []mispAttribute `json:"Attribute"`
			}{
				ID: "sched-1", Info: "Scheduler Wiring Test Event",
				GalaxyCluster: []mispGalaxy{
					{Type: "mitre-attack-pattern", Value: "PowerShell", Meta: struct {
						ExternalID []string `json:"external_id"`
						KillChain  []string `json:"kill_chain"`
					}{ExternalID: []string{"T1059.001"}}},
					{Type: "mitre-attack-pattern", Value: "Phishing", Meta: struct {
						ExternalID []string `json:"external_id"`
						KillChain  []string `json:"kill_chain"`
					}{ExternalID: []string{"T1566.001"}}},
					{Type: "mitre-malware", Value: "SchedulerTestMalware"},
				},
			}},
		})
		defer server.Close()

		mispClient := NewMISPClient(server.URL, "test-key", nil, nil)
		s := NewScheduler([]Source{mispClient}, NewGenerator(t.TempDir(), nil, nil, nil), scenario.NewEngine(t.TempDir()), 24, pool, nil)

		s.sync()

		campaigns, err := intelligence.ListCampaigns(context.Background(), pool)
		if err != nil {
			t.Fatalf("ListCampaigns: %v", err)
		}
		wantID := intelligence.NormalizeKey("Scheduler Wiring Test Event")
		found := false
		for _, c := range campaigns {
			if c.ID == wantID {
				found = true
			}
		}
		if !found {
			t.Errorf("campaigns = %+v, want one with ID=%q (the campaign's own normalized ID, not the raw MISP event ID)", campaigns, wantID)
		}

		malware, err := intelligence.ListMalware(context.Background(), pool)
		if err != nil {
			t.Fatalf("ListMalware: %v", err)
		}
		found = false
		for _, m := range malware {
			if m.Name == "SchedulerTestMalware" {
				found = true
			}
		}
		if !found {
			t.Errorf("malware = %+v, want one named SchedulerTestMalware", malware)
		}
	})
}

// TestUpsertActorProfiles_NilAliasesSectorsRegions_StillPersists is a
// regression test for a real pre-existing bug: pgx encodes a nil Go
// []string as SQL NULL, which violated threat_actor_profiles' NOT NULL
// text[] columns for any actor -- e.g. every MISP-sourced one, since
// extractActor never sets Aliases and Sectors/Regions stay nil whenever an
// event has no sector:/region: tag. This previously failed silently
// (upsertActorProfiles only logs), so the row was simply never written.
func TestUpsertActorProfiles_NilAliasesSectorsRegions_StillPersists(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		s.upsertActorProfiles([]ThreatActor{{
			Name: "NIL-FIELDS-TEST-ACTOR", Confidence: "medium",
			// Aliases, Sectors, Regions deliberately left nil.
		}})

		var aliases, sectors, regions []string
		err := pool.QueryRow(context.Background(),
			`SELECT aliases, sectors, regions FROM threat_actor_profiles WHERE name=$1`,
			"NIL-FIELDS-TEST-ACTOR").Scan(&aliases, &sectors, &regions)
		if err != nil {
			t.Fatalf("expected the profile row to exist, got: %v", err)
		}
		if aliases == nil || sectors == nil || regions == nil {
			t.Errorf("aliases=%v sectors=%v regions=%v, want empty slices not nil", aliases, sectors, regions)
		}
	})
}
