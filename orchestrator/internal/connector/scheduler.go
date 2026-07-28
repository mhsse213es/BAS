package connector

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/intelligence"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/threatpriority"
)

// Scheduler polls MISP and OpenCTI on a configurable interval and
// regenerates intel scenarios into the scenarios/intel/ directory.
type Scheduler struct {
	sources   []Source
	generator *Generator
	engine    *scenario.Engine
	interval  time.Duration
	// pool persists fetched actor profiles (sectors/regions) for
	// internal/reporting's priority-score weighting. See
	// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	pool *pgxpool.Pool

	// priorityEngine recomputes and snapshots Threat Prioritization scores
	// whenever intel changes -- connector sync IS the change-detection
	// trigger for internal/threatpriority's "Continuous Intelligence"
	// behavior, no separate polling needed. nil-safe: skipped if unset.
	priorityEngine *threatpriority.Engine

	mu     sync.RWMutex
	status ConnectorStatus
	syncCh chan struct{} // manual trigger
	stopCh chan struct{}
}

// NewScheduler creates a Scheduler over the given threat-intel sources (any of
// MISP, OpenCTI, BundleSource). An empty slice leaves the connector idle.
func NewScheduler(
	sources []Source,
	generator *Generator,
	engine *scenario.Engine,
	pollHours int,
	pool *pgxpool.Pool,
	priorityEngine *threatpriority.Engine,
) *Scheduler {
	if pollHours <= 0 {
		pollHours = 24
	}
	s := &Scheduler{
		sources:        sources,
		generator:      generator,
		engine:         engine,
		interval:       time.Duration(pollHours) * time.Hour,
		pool:           pool,
		priorityEngine: priorityEngine,
		syncCh:         make(chan struct{}, 1),
		stopCh:         make(chan struct{}),
	}
	s.status = ConnectorStatus{
		LastSyncStatus: "never",
		NextSyncAt:     time.Now().Add(s.interval),
	}
	for _, src := range sources {
		switch src.Name() {
		case "misp":
			s.status.MISPEnabled = true
		case "opencti":
			s.status.OpenCTIEnabled = true
		case "bundle":
			s.status.BundleEnabled = true
		}
	}
	return s
}

// Start launches the background polling goroutine.
func (s *Scheduler) Start() {
	if len(s.sources) == 0 {
		log.Println("[connector] no sources configured — connector idle")
		return
	}
	go s.run()
	log.Printf("[connector] scheduler started (interval: %s)", s.interval)

	// Run immediately on startup
	s.TriggerSync()
}

// Stop shuts down the scheduler gracefully.
func (s *Scheduler) Stop() {
	close(s.stopCh)
}

// TriggerSync requests an immediate sync (non-blocking; idempotent).
func (s *Scheduler) TriggerSync() {
	select {
	case s.syncCh <- struct{}{}:
	default: // already queued
	}
}

// Status returns a snapshot of the connector state.
func (s *Scheduler) Status() ConnectorStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

// ── background loop ───────────────────────────────────────────────────────────

func (s *Scheduler) run() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.sync()
		case <-s.syncCh:
			s.sync()
			// Reset ticker so we don't double-fire shortly after a manual sync
			ticker.Reset(s.interval)
		}
	}
}

func (s *Scheduler) sync() {
	log.Println("[connector] starting threat-intel sync")
	start := time.Now()

	var actors []ThreatActor
	var allCampaigns []intelligence.Campaign
	var allMalware []intelligence.Malware
	var bundleVersion string
	bySource := map[string]SourceStat{}

	// Fetch every configured source. The bundle (air-gapped floor) and live
	// providers (MISP/OpenCTI overlay) are treated uniformly; a single source
	// failing is logged and skipped, never aborting the others.
	for _, src := range s.sources {
		got, err := src.Fetch()
		if ss, ok := src.(StatsSource); ok {
			bySource[src.Name()] = ss.Stats()
		}
		if err != nil {
			log.Printf("[connector/%s] fetch error: %v", src.Name(), err)
			s.setError(src.Name()+": "+err.Error(), bySource)
			continue
		}
		log.Printf("[connector/%s] %d actors fetched", src.Name(), len(got))
		actors = append(actors, got...)
		if bs, ok := src.(*BundleSource); ok {
			bundleVersion = bs.Version()
		}
		if is, ok := src.(IntelligenceSource); ok {
			campaigns, malware, ierr := is.FetchIntelligence()
			if ierr != nil {
				log.Printf("[connector/%s] intelligence fetch error: %v", src.Name(), ierr)
			} else {
				allCampaigns = append(allCampaigns, campaigns...)
				allMalware = append(allMalware, malware...)
			}
		}
	}

	if len(actors) == 0 {
		log.Println("[connector] no actors returned from any source")
		s.setOK(0, 0, 0, bundleVersion, bySource)
		return
	}

	// Merge actors with the same name across sources — bundle floor + live
	// overlay compose here, since MergeActors unions their techniques.
	actors = MergeActors(actors)

	// Persist actor profiles (sectors/regions) for reporting's priority-score
	// weighting — see docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	s.upsertActorProfiles(actors)

	if s.pool != nil {
		for _, c := range allCampaigns {
			if err := intelligence.UpsertCampaign(context.Background(), s.pool, c); err != nil {
				log.Printf("[connector] upsert campaign %q: %v", c.ID, err)
			}
		}
		for _, m := range allMalware {
			if err := intelligence.UpsertMalware(context.Background(), s.pool, m); err != nil {
				log.Printf("[connector] upsert malware %q: %v", m.ID, err)
			}
		}
	}

	if s.priorityEngine != nil {
		if err := s.priorityEngine.SnapshotHistory(context.Background()); err != nil {
			log.Printf("[connector] threat-priority snapshot: %v", err)
		}
	}

	// ── Generate scenarios ────────────────────────────────────────────────
	result, err := s.generator.Write(actors)
	if err != nil {
		log.Printf("[connector/gen] write error: %v", err)
		s.setError("Generator: "+err.Error(), bySource)
		return
	}

	// ── Reload scenario engine ────────────────────────────────────────────
	if result.Created > 0 || result.Updated > 0 {
		if err := s.engine.Load(); err != nil {
			log.Printf("[connector] engine reload: %v", err)
		} else {
			log.Printf("[connector] scenario engine reloaded (%d total)", s.engine.Count())
		}
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	log.Printf("[connector] sync complete in %s — created:%d updated:%d skipped:%d",
		elapsed, result.Created, result.Updated, result.Skipped)

	s.setOK(result.Created, result.Updated, len(actors), bundleVersion, bySource)
}

func (s *Scheduler) setOK(created, updated, total int, bundleVersion string, bySource map[string]SourceStat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.LastSyncAt = time.Now()
	s.status.LastSyncStatus = "ok"
	s.status.LastError = ""
	s.status.ScenariosCreated += created
	s.status.ScenariosUpdated += updated
	s.status.TotalActors = total
	if bundleVersion != "" {
		s.status.BundleVersion = bundleVersion
	}
	s.status.BySource = bySource
	s.status.NextSyncAt = time.Now().Add(s.interval)
}

func (s *Scheduler) setError(msg string, bySource map[string]SourceStat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.LastSyncAt = time.Now()
	s.status.LastSyncStatus = "error"
	s.status.LastError = msg
	s.status.BySource = bySource
	s.status.NextSyncAt = time.Now().Add(s.interval)
}

// MergeActors combines actors with the same name (case-insensitive) from
// different sources into one actor with the union of their techniques.
func MergeActors(actors []ThreatActor) []ThreatActor {
	byName := make(map[string]*ThreatActor)
	for _, a := range actors {
		key := actorKey(a.Name)
		if existing, ok := byName[key]; ok {
			existing.Techniques = mergeTechniques(existing.Techniques, a.Techniques)
			if a.LastSeen.After(existing.LastSeen) {
				existing.LastSeen = a.LastSeen
			}
		} else {
			cp := a
			byName[key] = &cp
		}
	}
	out := make([]ThreatActor, 0, len(byName))
	for _, a := range byName {
		out = append(out, *a)
	}
	return out
}

func actorKey(name string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, " ", ""), "-", ""))
}

// upsertActorProfiles persists each actor's sectors/regions/aliases so
// internal/reporting can weight technique priority scores by sector/region
// relevance. A single actor's upsert failing is logged and skipped, never
// aborting the rest — same discipline sync() already applies to source
// fetches. No-op when pool is nil (e.g. a test that never calls sync()).
func (s *Scheduler) upsertActorProfiles(actors []ThreatActor) {
	if s.pool == nil {
		return
	}
	ctx := context.Background()
	for _, a := range actors {
		var lastSeen *time.Time
		if !a.LastSeen.IsZero() {
			t := a.LastSeen
			lastSeen = &t
		}
		_, err := s.pool.Exec(ctx,
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source, last_seen, confidence, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
			 ON CONFLICT (name) DO UPDATE SET
			   aliases = EXCLUDED.aliases, sectors = EXCLUDED.sectors, regions = EXCLUDED.regions,
			   source = EXCLUDED.source, last_seen = EXCLUDED.last_seen, confidence = EXCLUDED.confidence,
			   updated_at = NOW()`,
			a.Name, a.Aliases, a.Sectors, a.Regions, a.Source, lastSeen, a.Confidence)
		if err != nil {
			log.Printf("[connector] upsert actor profile %q: %v", a.Name, err)
		}
	}
}
