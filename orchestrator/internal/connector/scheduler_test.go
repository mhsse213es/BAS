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

func TestUpsertActorProfiles_PersistsCanonicalGroupID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		s.upsertActorProfiles([]ThreatActor{{
			Name: "APT-CANONICAL-TEST", CanonicalGroupID: "G0016",
			Aliases: []string{}, Sectors: []string{}, Regions: []string{},
		}})

		var canonicalGroupID string
		err := pool.QueryRow(t.Context(),
			`SELECT canonical_group_id FROM threat_actor_profiles WHERE name=$1`, "APT-CANONICAL-TEST").Scan(&canonicalGroupID)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if canonicalGroupID != "G0016" {
			t.Fatalf("canonical_group_id = %q, want %q", canonicalGroupID, "G0016")
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

// TestUpsertActorSources_TwoSourcesSameActorProduceTwoRows is the core of
// this project: MISP and OpenCTI describing the same real-world actor
// collapse into ONE threat_actor_profiles row (first-arrival-wins), but
// each must keep its OWN record here -- its own name, its own sectors, its
// own confidence -- so "why does Audspect believe this actor is relevant"
// is answerable per source.
func TestUpsertActorSources_TwoSourcesSameActorProduceTwoRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		raw := []ThreatActor{
			{Name: "PROV-Wizard Spider", Source: "misp", SourceID: "evt-1",
				Sectors: []string{"financial services"}, Confidence: "high",
				Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}}},
			{Name: "PROV-Sangria Tempest", Source: "opencti", SourceID: "ta-9",
				Aliases: []string{"PROV-Wizard Spider"}, Confidence: "medium",
				Techniques: []TechniqueRef{{ID: "T1078"}}},
		}
		merged, groups := MergeActorsWithProvenance(raw)
		if len(merged) != 1 {
			t.Fatalf("fixture precondition: want the two actors to merge, got %d", len(merged))
		}
		// The FK requires the parent profile row first -- same ordering
		// sync() itself uses.
		s.upsertActorProfiles(merged)
		s.upsertActorSources(raw, merged, groups)

		rows, err := pool.Query(t.Context(),
			`SELECT source, source_id, name, sectors, confidence, technique_count
			   FROM threat_actor_sources WHERE actor_name = $1 ORDER BY source`, merged[0].Name)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		defer rows.Close()
		type row struct {
			source, sourceID, name, confidence string
			sectors                            []string
			techniqueCount                     int
		}
		var got []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.source, &r.sourceID, &r.name, &r.sectors, &r.confidence, &r.techniqueCount); err != nil {
				t.Fatalf("scan: %v", err)
			}
			got = append(got, r)
		}
		if len(got) != 2 {
			t.Fatalf("got %d source rows, want 2 (one per contributing source): %+v", len(got), got)
		}
		// ORDER BY source -> misp, opencti
		if got[0].source != "misp" || got[0].name != "PROV-Wizard Spider" ||
			got[0].confidence != "high" || got[0].techniqueCount != 2 ||
			len(got[0].sectors) != 1 || got[0].sectors[0] != "financial services" {
			t.Errorf("misp row = %+v, want its OWN name/sectors/confidence/technique count", got[0])
		}
		if got[1].source != "opencti" || got[1].name != "PROV-Sangria Tempest" ||
			got[1].confidence != "medium" || got[1].techniqueCount != 1 ||
			len(got[1].sectors) != 0 {
			t.Errorf("opencti row = %+v, want its OWN name/confidence/technique count and empty sectors", got[1])
		}
	})
}

// TestUpsertActorSources_Idempotent proves a second sync with unchanged
// data updates in place rather than accumulating duplicate rows.
func TestUpsertActorSources_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		raw := []ThreatActor{
			{Name: "PROV-IDEMPOTENT", Source: "misp", Confidence: "high", Techniques: []TechniqueRef{{ID: "T1059.001"}}},
		}
		merged, groups := MergeActorsWithProvenance(raw)
		s.upsertActorProfiles(merged)
		s.upsertActorSources(raw, merged, groups)
		s.upsertActorSources(raw, merged, groups)

		var count int
		if err := pool.QueryRow(t.Context(),
			`SELECT COUNT(*) FROM threat_actor_sources WHERE actor_name = $1`, "PROV-IDEMPOTENT").Scan(&count); err != nil {
			t.Fatalf("query: %v", err)
		}
		if count != 1 {
			t.Fatalf("row count = %d after two upserts, want 1", count)
		}
	})
}

// TestScheduler_SyncPersistsPerSourceProvenance exercises the real sync()
// path end to end -- proving the pre-merge list actually survives to
// upsertActorSources rather than being flattened away by MergeActors.
func TestScheduler_SyncPersistsPerSourceProvenance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := NewScheduler([]Source{
			fakeSource{name: "misp", actors: []ThreatActor{{
				Name: "SYNC-PROV-ACTOR", Source: "misp", Sectors: []string{"government"},
				Confidence: "high", Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}},
			}}},
			fakeSource{name: "opencti", actors: []ThreatActor{{
				Name: "SYNC-PROV-ALIAS", Aliases: []string{"SYNC-PROV-ACTOR"}, Source: "opencti",
				Confidence: "medium", Techniques: []TechniqueRef{{ID: "T1078"}},
			}}},
		}, NewGenerator(t.TempDir(), nil, nil, nil), scenario.NewEngine(t.TempDir()), 24, pool, nil)

		s.sync()

		var sources []string
		rows, err := pool.Query(t.Context(),
			`SELECT source FROM threat_actor_sources WHERE actor_name = $1 ORDER BY source`, "SYNC-PROV-ACTOR")
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var src string
			if err := rows.Scan(&src); err != nil {
				t.Fatalf("scan: %v", err)
			}
			sources = append(sources, src)
		}
		if len(sources) != 2 || sources[0] != "misp" || sources[1] != "opencti" {
			t.Fatalf("sources = %v, want [misp opencti] -- both contributing sources preserved through sync()", sources)
		}
	})
}

type fakeActivitySource struct {
	name    string
	signals []ActivitySignal
	err     error
}

func (f fakeActivitySource) Name() string                             { return f.name }
func (f fakeActivitySource) FetchActivity() ([]ActivitySignal, error) { return f.signals, f.err }

// TestUpsertActivitySignals_MatchesExistingActor_LeavesCuratedFieldsUntouched
// is the core regression guard for the bug this whole sub-project exists to
// fix: an activity signal for an actor that already has curated
// intelligence must NOT touch that actor's Confidence or LastSeen.
func TestUpsertActivitySignals_MatchesExistingActor_LeavesCuratedFieldsUntouched(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		curatedSeen := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		s.upsertActorProfiles([]ThreatActor{{
			Name: "ACT-Wizard Spider", Confidence: "high", LastSeen: curatedSeen,
			Aliases: []string{}, Sectors: []string{}, Regions: []string{},
		}})

		first := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
		last := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
		s.upsertActivitySignals("otx", []ActivitySignal{
			{ActorName: "ACT-Wizard Spider", PulseCount: 3, FirstObserved: first, LastObserved: last},
		}, []ThreatActor{{Name: "ACT-Wizard Spider"}})

		var confidence string
		var lastSeen time.Time
		if err := pool.QueryRow(t.Context(),
			`SELECT confidence, last_seen FROM threat_actor_profiles WHERE name = $1`, "ACT-Wizard Spider",
		).Scan(&confidence, &lastSeen); err != nil {
			t.Fatalf("query profile: %v", err)
		}
		if confidence != "high" || !lastSeen.Equal(curatedSeen) {
			t.Fatalf("profile confidence/lastSeen = %q/%v, want untouched (high/%v)", confidence, lastSeen, curatedSeen)
		}

		var pulseCount int
		var gotFirst, gotLast time.Time
		if err := pool.QueryRow(t.Context(),
			`SELECT pulse_count, first_observed, last_observed FROM threat_actor_activity WHERE actor_name = $1 AND source = 'otx'`,
			"ACT-Wizard Spider",
		).Scan(&pulseCount, &gotFirst, &gotLast); err != nil {
			t.Fatalf("query activity: %v", err)
		}
		if pulseCount != 3 || !gotFirst.Equal(first) || !gotLast.Equal(last) {
			t.Fatalf("activity row = pulseCount=%d first=%v last=%v, want 3/%v/%v", pulseCount, gotFirst, gotLast, first, last)
		}
	})
}

// TestUpsertActivitySignals_NoMatch_CreatesMinimalStub covers the
// user-approved orphan path: a MITRE-named actor no curated source has
// ever reported gets a bare threat_actor_profiles row so its activity has
// somewhere to attach.
func TestUpsertActivitySignals_NoMatch_CreatesMinimalStub(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		ts := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
		s.upsertActivitySignals("otx", []ActivitySignal{
			{ActorName: "ACT-Orphan Group", PulseCount: 1, FirstObserved: ts, LastObserved: ts},
		}, nil) // no curated actors at all

		var confidence string
		var lastSeen *time.Time
		if err := pool.QueryRow(t.Context(),
			`SELECT confidence, last_seen FROM threat_actor_profiles WHERE name = $1`, "ACT-Orphan Group",
		).Scan(&confidence, &lastSeen); err != nil {
			t.Fatalf("expected a minimal stub profile row: %v", err)
		}
		if confidence != "" || lastSeen != nil {
			t.Fatalf("stub confidence/lastSeen = %q/%v, want empty/nil (nothing curated ever said this)", confidence, lastSeen)
		}

		var pulseCount int
		if err := pool.QueryRow(t.Context(),
			`SELECT pulse_count FROM threat_actor_activity WHERE actor_name = $1 AND source = 'otx'`, "ACT-Orphan Group",
		).Scan(&pulseCount); err != nil {
			t.Fatalf("expected an activity row attached to the stub: %v", err)
		}
		if pulseCount != 1 {
			t.Fatalf("pulseCount = %d, want 1", pulseCount)
		}
	})
}

// TestUpsertActivitySignals_LeastGreatestAcrossTwoSyncs proves
// first_observed/last_observed never regress due to OTX subscription
// churn -- a pulse rolling off the feed must not make an actor's earliest
// or latest recorded activity look narrower than it really is.
func TestUpsertActivitySignals_LeastGreatestAcrossTwoSyncs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		s.upsertActorProfiles([]ThreatActor{{
			Name: "ACT-Churn Actor", Aliases: []string{}, Sectors: []string{}, Regions: []string{},
		}})
		merged := []ThreatActor{{Name: "ACT-Churn Actor"}}

		aug10 := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
		s.upsertActivitySignals("otx", []ActivitySignal{
			{ActorName: "ACT-Churn Actor", PulseCount: 1, FirstObserved: aug10, LastObserved: aug10},
		}, merged)

		aug5 := time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)
		aug15 := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
		s.upsertActivitySignals("otx", []ActivitySignal{
			{ActorName: "ACT-Churn Actor", PulseCount: 2, FirstObserved: aug5, LastObserved: aug15},
		}, merged)

		var pulseCount int
		var gotFirst, gotLast time.Time
		if err := pool.QueryRow(t.Context(),
			`SELECT pulse_count, first_observed, last_observed FROM threat_actor_activity WHERE actor_name = $1 AND source = 'otx'`,
			"ACT-Churn Actor",
		).Scan(&pulseCount, &gotFirst, &gotLast); err != nil {
			t.Fatalf("query: %v", err)
		}
		if pulseCount != 2 {
			t.Errorf("pulseCount = %d, want 2 (plain overwrite, a snapshot of the latest sync)", pulseCount)
		}
		if !gotFirst.Equal(aug5) {
			t.Errorf("first_observed = %v, want %v (LEAST of aug10 and aug5)", gotFirst, aug5)
		}
		if !gotLast.Equal(aug15) {
			t.Errorf("last_observed = %v, want %v (GREATEST of aug10 and aug15)", gotLast, aug15)
		}
	})
}

// TestScheduler_Sync_ProcessesActivitySignalsEvenWithZeroCuratedActors
// proves an OTX-only deployment (no MISP/OpenCTI/Bundle configured, or all
// three returned nothing this sync) still gets its activity signals
// processed -- the pre-existing "no actors returned from any source" early
// return must not swallow activity-only syncs.
func TestScheduler_Sync_ProcessesActivitySignalsEvenWithZeroCuratedActors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := NewScheduler(nil, NewGenerator(t.TempDir(), nil, nil, nil), scenario.NewEngine(t.TempDir()), 24, pool, nil)
		ts := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
		s.WithActivitySources([]ActivitySource{fakeActivitySource{
			name: "otx",
			signals: []ActivitySignal{
				{ActorName: "SYNC-ACT-ONLY", PulseCount: 5, FirstObserved: ts, LastObserved: ts},
			},
		}})

		s.sync()

		var pulseCount int
		if err := pool.QueryRow(t.Context(),
			`SELECT pulse_count FROM threat_actor_activity WHERE actor_name = $1 AND source = 'otx'`, "SYNC-ACT-ONLY",
		).Scan(&pulseCount); err != nil {
			t.Fatalf("expected an activity row even with zero curated sources: %v", err)
		}
		if pulseCount != 5 {
			t.Fatalf("pulseCount = %d, want 5", pulseCount)
		}
	})
}

func TestWithActivitySources_SetsOTXEnabledStatus(t *testing.T) {
	s := NewScheduler(nil, nil, nil, 24, nil, nil)
	s.WithActivitySources([]ActivitySource{fakeActivitySource{name: "otx"}})
	if !s.Status().OTXEnabled {
		t.Error("OTXEnabled should be true after WithActivitySources with an otx source")
	}
}

func TestReconfigureActivitySources_UpdatesOTXEnabledStatus(t *testing.T) {
	s := NewScheduler(nil, nil, nil, 24, nil, nil)
	s.WithActivitySources([]ActivitySource{fakeActivitySource{name: "otx"}})
	s.ReconfigureActivitySources(nil)
	if s.Status().OTXEnabled {
		t.Error("OTXEnabled should be false after reconfiguring OTX out")
	}
}

// TestUpsertActorProfiles_PersistsTechniques proves the merged actor's
// technique IDs survive into threat_actor_profiles.techniques -- the data
// Threat Prioritization's scoreActor falls back to when no MITRE-name
// match exists for this actor. Deduped and uppercased, same discipline
// Generator.buildYAML already applies for the generated scenario's
// art_techniques list.
func TestUpsertActorProfiles_PersistsTechniques(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		s.upsertActorProfiles([]ThreatActor{{
			Name: "APT-TECH-PERSIST-TEST",
			Techniques: []TechniqueRef{
				{ID: "t1059.001"}, {ID: "T1566.001"}, {ID: "t1059.001"}, // duplicate, mixed case
			},
			Aliases: []string{}, Sectors: []string{}, Regions: []string{},
		}})

		var techs []string
		err := pool.QueryRow(t.Context(),
			`SELECT techniques FROM threat_actor_profiles WHERE name=$1`, "APT-TECH-PERSIST-TEST").Scan(&techs)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if len(techs) != 2 {
			t.Fatalf("techniques = %v, want 2 deduped entries", techs)
		}
		want := map[string]bool{"T1059.001": true, "T1566.001": true}
		for _, id := range techs {
			if !want[id] {
				t.Errorf("unexpected technique %q in %v", id, techs)
			}
		}
	})
}

func TestUpsertActorProfiles_NoTechniques_PersistsEmptyArray(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		s.upsertActorProfiles([]ThreatActor{{
			Name: "APT-NO-TECH-TEST", Aliases: []string{}, Sectors: []string{}, Regions: []string{},
		}})

		var techs []string
		err := pool.QueryRow(t.Context(),
			`SELECT techniques FROM threat_actor_profiles WHERE name=$1`, "APT-NO-TECH-TEST").Scan(&techs)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if len(techs) != 0 {
			t.Fatalf("techniques = %v, want empty", techs)
		}
	})
}
