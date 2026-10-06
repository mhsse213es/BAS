package connector

import (
	"fmt"
	"context"
	"log"
	"os"
	"path/filepath"
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
	sources         []Source
	activitySources []ActivitySource // OTX today -- see WithActivitySources
	generator       *Generator
	engine          *scenario.Engine
	interval        time.Duration
	// pool persists fetched actor profiles (sectors/regions) for
	// internal/reporting's priority-score weighting. See
	// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	pool *pgxpool.Pool

	// priorityEngine recomputes and snapshots Threat Prioritization scores
	// whenever intel changes -- connector sync IS the change-detection
	// trigger for internal/threatpriority's "Continuous Intelligence"
	// behavior, no separate polling needed. nil-safe: skipped if unset.
	priorityEngine *threatpriority.Engine

	// mu now also guards sources (not just status) -- Reconfigure (added for
	// live, restart-free config changes; see
	// docs/superpowers/specs/2026-08-10-threat-intel-connector-config-design.md)
	// mutates sources concurrently with sync()'s background-goroutine read of
	// it, which was previously unprotected since sources never changed after
	// construction.
	mu      sync.RWMutex
	status  ConnectorStatus
	started bool          // true once run() has actually been launched (by Start or Reconfigure)
	syncCh  chan struct{} // manual trigger
	stopCh  chan struct{}

	// bundleDir/bundleVerify let the scheduler own the bundle source's
	// presence itself (see WithBundleDir/checkBundleSource), instead of
	// relying on main.go's one-time boot check. Two problems otherwise: a
	// bundle file dropped in after boot (none present at startup) was never
	// picked up short of a restart, since nothing ever re-checked; and any
	// MISP/OpenCTI/OTX config save called Reconfigure with a DB-loaded
	// source list that never included the bundle at all, silently dropping
	// an already-working bundle source from the very next sync onward.
	bundleDir    string
	bundleVerify func(string) error
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

// Start launches the background polling goroutine. Also starts with zero
// sources when a bundle directory is configured (WithBundleDir), even if
// no bundle file is present yet -- otherwise a bundle dropped in later, on
// a deployment with no MISP/OpenCTI/OTX ever configured either, would have
// no running sync loop to be picked up by, and would need a restart after
// all despite checkBundleSource existing.
func (s *Scheduler) Start() {
	if len(s.sources) == 0 && s.bundleDir == "" {
		log.Println("[connector] no sources configured — connector idle")
		return
	}
	s.mu.Lock()
	s.started = true
	s.mu.Unlock()
	go s.run()
	log.Printf("[connector] scheduler started (interval: %s)", s.interval)

	// Run immediately on startup
	s.TriggerSync()
}

// WithBundleDir attaches the air-gapped bundle directory + signature
// verifier so the scheduler can (re-)detect the bundle source itself on
// every sync, rather than only once at construction. Safe to call once
// after NewScheduler, before Start. Chainable. Pass dir="" to disable
// bundle checking entirely (matches the existing "TIBundleDir unset"
// behavior in main.go).
func (s *Scheduler) WithBundleDir(dir string, verify func(string) error) *Scheduler {
	s.mu.Lock()
	s.bundleDir = dir
	s.bundleVerify = verify
	s.mu.Unlock()
	return s
}

// checkBundleSource re-detects the bundle file's presence and keeps
// s.sources/s.status.BundleEnabled in sync with it, called at the top of
// every sync() -- both the periodic tick and any manually/config-save-
// triggered one. Registers a BundleSource the first time the file appears
// (no restart needed), and de-registers it if the file is later removed,
// without disturbing any other source already in the list.
func (s *Scheduler) checkBundleSource() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bundleDir == "" {
		return
	}
	present := false
	if _, err := os.Stat(filepath.Join(s.bundleDir, BundleFileName)); err == nil {
		present = true
	}
	haveIdx := -1
	for i, src := range s.sources {
		if _, ok := src.(*BundleSource); ok {
			haveIdx = i
			break
		}
	}
	switch {
	case present && haveIdx == -1:
		s.sources = append(s.sources, NewBundleSource(s.bundleDir, s.bundleVerify))
		s.status.BundleEnabled = true
		log.Printf("[connector] bundle file detected at %s — registered, no restart needed", s.bundleDir)
	case !present && haveIdx != -1:
		s.sources = append(s.sources[:haveIdx], s.sources[haveIdx+1:]...)
		s.status.BundleEnabled = false
		log.Printf("[connector] bundle file no longer present at %s — de-registered", s.bundleDir)
	}
}

// Reconfigure replaces the source list live -- no restart needed. If the
// scheduler was constructed with zero sources (Start saw len(sources)==0
// and never launched the background goroutine, e.g. a fresh install with
// nothing configured yet), Reconfigure launches it now, exactly as if those
// sources had been present at boot. Safe to call repeatedly; only the first
// call that transitions from idle to non-idle actually starts the goroutine.
func (s *Scheduler) Reconfigure(sources []Source) {
	s.mu.Lock()
	s.sources = sources
	s.status.MISPEnabled = false
	s.status.OpenCTIEnabled = false
	s.status.BundleEnabled = false
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
	shouldStart := !s.started && len(sources) > 0
	if shouldStart {
		s.started = true
	}
	s.mu.Unlock()

	// Restore the bundle source immediately if it was already registered --
	// sources above came from LoadSourcesFromDB (MISP/OpenCTI/OTX only), so
	// without this, saving any one of those three would silently drop an
	// already-working bundle source until the next sync tick noticed it was
	// gone via checkBundleSource on its own.
	s.checkBundleSource()

	if shouldStart {
		go s.run()
		log.Printf("[connector] scheduler started via Reconfigure (interval: %s)", s.interval)
		s.TriggerSync()
	}
}

// WithActivitySources attaches activity-evidence sources (currently just
// OTX) -- kept structurally separate from sources/Reconfigure because
// ActivitySource is a different interface (FetchActivity, not Fetch): it
// contributes activity evidence about already-known actors, never curated
// attribution. Safe to call once after NewScheduler, before Start. Chainable.
func (s *Scheduler) WithActivitySources(sources []ActivitySource) *Scheduler {
	s.mu.Lock()
	s.activitySources = sources
	s.status.OTXEnabled = false
	for _, src := range sources {
		if src.Name() == "otx" {
			s.status.OTXEnabled = true
		}
	}
	s.mu.Unlock()
	return s
}

// ReconfigureActivitySources live-updates the activity-source list,
// mirroring Reconfigure's live-update semantics for curated sources but
// kept as a separate method since ActivitySource is a distinct interface.
// Does not itself trigger a sync -- callers that want one call TriggerSync
// explicitly, same as internal/api/threat_intel_config_handlers.go already
// does after Reconfigure.
func (s *Scheduler) ReconfigureActivitySources(sources []ActivitySource) {
	s.mu.Lock()
	s.activitySources = sources
	s.status.OTXEnabled = false
	for _, src := range sources {
		if src.Name() == "otx" {
			s.status.OTXEnabled = true
		}
	}
	s.mu.Unlock()
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
	// Re-detect the bundle file's presence before touching s.sources below,
	// so a bundle dropped in since the last tick is picked up this cycle
	// with no restart needed.
	s.checkBundleSource()

	log.Println("[connector] starting threat-intel sync")
	start := time.Now()

	var actors []ThreatActor
	var allCampaigns []intelligence.Campaign
	var allMalware []intelligence.Malware
	var allTools []intelligence.Tool
	var bundleVersion string
	bySource := map[string]SourceStat{}

	// Fetch every configured source. The bundle (air-gapped floor) and live
	// providers (MISP/OpenCTI overlay) are treated uniformly; a single source
	// failing is logged and skipped, never aborting the others.
	// Take a local copy under lock -- Reconfigure can replace s.sources
	// concurrently with this background goroutine's read of it.
	s.mu.RLock()
	sources := s.sources
	activitySources := s.activitySources
	s.mu.RUnlock()
	var techEvidence []TechniqueEvidence
	for _, src := range sources {
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
			campaigns, malware, tools, ierr := is.FetchIntelligence()
			if ierr != nil {
				log.Printf("[connector/%s] intelligence fetch error: %v", src.Name(), ierr)
			} else {
				allCampaigns = append(allCampaigns, campaigns...)
				allMalware = append(allMalware, malware...)
				allTools = append(allTools, tools...)
			}
		}
		if tes, ok := src.(TechniqueEvidenceSource); ok {
			techEvidence = append(techEvidence, tes.FetchTechniqueEvidence()...)
		}
	}

	// Fetch activity sources (OTX) independently of curated sources' outcome
	// -- a signal must still be processed, and can still create an orphan
	// stub, even when zero curated sources returned anything (e.g. an
	// OTX-only deployment). See
	// docs/superpowers/specs/2026-08-12-otx-activity-signal-design.md.
	type activityFetch struct {
		source  string
		signals []ActivitySignal
	}
	var activityResults []activityFetch
	for _, asrc := range activitySources {
		signals, err := asrc.FetchActivity()
		if ss, ok := asrc.(StatsSource); ok {
			bySource[asrc.Name()] = ss.Stats()
		}
		if err != nil {
			log.Printf("[connector/%s] fetch error: %v", asrc.Name(), err)
			continue
		}
		log.Printf("[connector/%s] %d activity signals fetched", asrc.Name(), len(signals))
		activityResults = append(activityResults, activityFetch{source: asrc.Name(), signals: signals})
	}

	if len(actors) == 0 && len(activityResults) == 0 {
		log.Println("[connector] no actors returned from any source")
		s.setOK(0, 0, 0, bundleVersion, bySource)
		return
	}

	// Merge actors with the same name across sources — bundle floor + live
	// overlay compose here, since MergeActors unions their techniques.
	// rawActors keeps the pre-merge list alive: the merged result
	// deliberately flattens away each source's own assertions, which
	// upsertActorSources below persists separately.
	rawActors := actors
	merged, groups := MergeActorsWithProvenance(rawActors)
	actors = merged

	// Persist actor profiles (sectors/regions) for reporting's priority-score
	// weighting — see docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	s.upsertActorProfiles(actors)
	// Per-source provenance. MUST run after upsertActorProfiles -- these rows
	// carry a foreign key to threat_actor_profiles(name).
	s.upsertActorSources(rawActors, actors, groups)
	// Activity evidence -- resolved against the now-merged curated roster,
	// or given a minimal stub if nothing curated matches. MUST also run
	// after upsertActorProfiles for the same FK reason.
	for _, r := range activityResults {
		s.upsertActivitySignals(r.source, r.signals, actors)
	}
	// Per-relationship technique evidence (OpenCTI only) -- resolved
	// against the merged roster; unlike activity signals, an unresolved
	// actor's evidence is dropped, not stubbed (this enriches an actor
	// that must already exist via a curated source).
	s.upsertTechniqueEvidence(techEvidence, actors)

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
		for _, tl := range allTools {
			if err := intelligence.UpsertTool(context.Background(), s.pool, tl); err != nil {
				log.Printf("[connector] upsert tool %q: %v", tl.ID, err)
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
	if result.Created > 0 || result.Updated > 0 || result.Changed > 0 {
		if err := s.engine.Load(); err != nil {
			log.Printf("[connector] engine reload: %v", err)
		} else {
			log.Printf("[connector] scenario engine reloaded (%d total)", s.engine.Count())
		}
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	log.Printf("[connector] sync complete in %s — created:%d updated:%d skipped:%d changed:%d failed:%d",
		elapsed, result.Created, result.Updated, result.Skipped, result.Changed, result.Failed)

	s.setOK(result.Created, result.Updated, len(actors), bundleVersion, bySource)
	if result.Failed > 0 {
		s.mu.Lock()
		s.status.LastSyncStatus = "error"
		s.status.LastError = fmt.Sprintf("Generator: %d candidate(s) failed registration (see logs)", result.Failed)
		s.mu.Unlock()
	}
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

// upsertActorProfiles persists each actor's sectors/regions/aliases so
// internal/reporting can weight technique priority scores by sector/region
// relevance. A single actor's upsert failing is logged and skipped, never
// aborting the rest — same discipline sync() already applies to source
// fetches. No-op when pool is nil (e.g. a test that never calls sync()).
// nonNilStrings coalesces a nil slice to an empty one. pgx encodes a nil
// []string as SQL NULL rather than an empty array, which violates
// threat_actor_profiles' NOT NULL text[] columns (aliases/sectors/regions)
// for any ThreatActor that leaves a field unset -- e.g. MISPClient's
// extractActor never populates Aliases at all, and Sectors/Regions stay nil
// whenever an event carries no sector:/region: tag, both common cases. This
// previously failed silently (upsertActorProfiles only logs the error), so
// every such actor's profile row was never written despite Fetch()
// reporting success.
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

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
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source, last_seen, confidence, canonical_group_id, techniques, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
			 ON CONFLICT (name) DO UPDATE SET
			   aliases = EXCLUDED.aliases, sectors = EXCLUDED.sectors, regions = EXCLUDED.regions,
			   source = EXCLUDED.source, last_seen = EXCLUDED.last_seen, confidence = EXCLUDED.confidence,
			   canonical_group_id = EXCLUDED.canonical_group_id, techniques = EXCLUDED.techniques,
			   updated_at = NOW()`,
			a.Name, nonNilStrings(a.Aliases), nonNilStrings(a.Sectors), nonNilStrings(a.Regions), a.Source, lastSeen, a.Confidence, a.CanonicalGroupID, dedupedTechniqueIDs(a.Techniques))
		if err != nil {
			log.Printf("[connector] upsert actor profile %q: %v", a.Name, err)
		}
	}
}

// upsertActorSources persists each source's OWN raw, pre-merge assertions
// about an actor -- one row per (canonical actor, source). rawActors is the
// combined pre-merge list exactly as fetched; merged[i] is the survivor
// that groups[i]'s raw actors collapsed into (see
// MergeActorsWithProvenance). Purely additive provenance:
// upsertActorProfiles' own first-arrival-wins merged row is written
// separately and is unaffected by anything here.
//
// Two raw actors from the SAME source merging into one canonical actor
// (e.g. two MISP events about the same group) collide on the
// (actor_name, source) key, so the later one wins -- this row answers
// "what does this source say about this actor", not "every record this
// source holds". Per-record granularity is sub-project #3's job.
//
// A single row failing is logged and skipped, never aborting the rest --
// same discipline upsertActorProfiles already applies. No-op when pool is
// nil (e.g. a test that never calls sync()).
func (s *Scheduler) upsertActorSources(rawActors, merged []ThreatActor, groups [][]int) {
	if s.pool == nil {
		return
	}
	ctx := context.Background()
	for gi, idxs := range groups {
		if gi >= len(merged) {
			continue // defensive: groups is index-aligned with merged by construction
		}
		actorName := merged[gi].Name
		for _, ri := range idxs {
			if ri >= len(rawActors) {
				continue
			}
			raw := rawActors[ri]
			if raw.Source == "" {
				continue // nothing to attribute this record to
			}
			var lastSeen *time.Time
			if !raw.LastSeen.IsZero() {
				t := raw.LastSeen
				lastSeen = &t
			}
			_, err := s.pool.Exec(ctx,
				`INSERT INTO threat_actor_sources
				   (actor_name, source, source_id, name, aliases, sectors, regions, confidence, technique_count, last_seen, updated_at)
				 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
				 ON CONFLICT (actor_name, source) DO UPDATE SET
				   source_id = EXCLUDED.source_id, name = EXCLUDED.name,
				   aliases = EXCLUDED.aliases, sectors = EXCLUDED.sectors, regions = EXCLUDED.regions,
				   confidence = EXCLUDED.confidence, technique_count = EXCLUDED.technique_count,
				   last_seen = EXCLUDED.last_seen, updated_at = NOW()`,
				actorName, raw.Source, raw.SourceID, raw.Name,
				nonNilStrings(raw.Aliases), nonNilStrings(raw.Sectors), nonNilStrings(raw.Regions),
				raw.Confidence, len(raw.Techniques), lastSeen)
			if err != nil {
				log.Printf("[connector] upsert actor source %q/%q: %v", actorName, raw.Source, err)
			}
		}
	}
}

// resolveActivitySignalActor looks up an activity signal's actor name
// against the already-merged curated roster, reusing actorKey's exact-match
// normalization (actor_merge.go) -- no fuzzy/similarity matching,
// consistent with MergeActors' own matching discipline. Returns the merged
// actor's own Name (its canonical casing) on a match.
func resolveActivitySignalActor(signalName string, merged []ThreatActor) (string, bool) {
	key := actorKey(signalName)
	for _, m := range merged {
		if actorKey(m.Name) == key {
			return m.Name, true
		}
		for _, alias := range m.Aliases {
			if actorKey(alias) == key {
				return m.Name, true
			}
		}
	}
	return "", false
}

// upsertActivitySignals resolves each signal against the merged curated
// roster and persists to threat_actor_activity. A signal matching nothing
// curated gets a minimal threat_actor_profiles stub (bare name; every
// other column keeps the table's own default -- ” confidence, NULL
// last_seen) so the activity has somewhere to attach.
// internal/reporting/insights.go's ResolveActorTechniques independently
// re-derives the actor's MITRE technique list from its Name at scoring
// time, so the stub needs nothing else. A single signal failing is logged
// and skipped, never aborting the rest -- same discipline
// upsertActorProfiles/upsertActorSources already apply. No-op when pool is
// nil.
func (s *Scheduler) upsertActivitySignals(source string, signals []ActivitySignal, merged []ThreatActor) {
	if s.pool == nil {
		return
	}
	ctx := context.Background()
	for _, sig := range signals {
		actorName, found := resolveActivitySignalActor(sig.ActorName, merged)
		if !found {
			actorName = sig.ActorName
			if _, err := s.pool.Exec(ctx,
				`INSERT INTO threat_actor_profiles (name, updated_at) VALUES ($1, NOW())
				 ON CONFLICT (name) DO NOTHING`,
				actorName); err != nil {
				log.Printf("[connector] create activity stub profile %q: %v", actorName, err)
				continue
			}
		}
		_, err := s.pool.Exec(ctx,
			`INSERT INTO threat_actor_activity (actor_name, source, pulse_count, first_observed, last_observed, updated_at)
			 VALUES ($1,$2,$3,$4,$5,NOW())
			 ON CONFLICT (actor_name, source) DO UPDATE SET
			   pulse_count = EXCLUDED.pulse_count,
			   first_observed = LEAST(threat_actor_activity.first_observed, EXCLUDED.first_observed),
			   last_observed = GREATEST(threat_actor_activity.last_observed, EXCLUDED.last_observed),
			   updated_at = NOW()`,
			actorName, source, sig.PulseCount, sig.FirstObserved, sig.LastObserved)
		if err != nil {
			log.Printf("[connector] upsert activity signal %q/%q: %v", actorName, source, err)
		}
	}
}

// upsertTechniqueEvidence resolves each evidence record against the
// merged curated roster (reusing resolveActivitySignalActor, unmodified)
// and persists to technique_evidence. Unlike upsertActivitySignals, a
// record that doesn't resolve to an existing actor is dropped and
// logged -- this enriches an actor a curated source must already have
// established, it never creates one. A single record failing is logged
// and skipped, never aborting the rest -- same discipline every other
// upsert* function in this file applies. No-op when pool is nil.
func (s *Scheduler) upsertTechniqueEvidence(evidence []TechniqueEvidence, merged []ThreatActor) {
	if s.pool == nil {
		return
	}
	ctx := context.Background()
	for _, ev := range evidence {
		actorName, found := resolveActivitySignalActor(ev.ActorName, merged)
		if !found {
			log.Printf("[connector] technique evidence for unresolved actor %q dropped (technique %s)", ev.ActorName, ev.TechniqueID)
			continue
		}
		_, err := s.pool.Exec(ctx,
			`INSERT INTO technique_evidence (actor_name, technique_id, via, via_name, source, confidence, start_time, stop_time, updated_at)
			 VALUES ($1,$2,$3,$4,'opencti',$5,$6,$7,NOW())
			 ON CONFLICT (actor_name, technique_id, via, via_name, source) DO UPDATE SET
			   confidence = EXCLUDED.confidence, start_time = EXCLUDED.start_time,
			   stop_time = EXCLUDED.stop_time, updated_at = NOW()`,
			actorName, ev.TechniqueID, ev.Via, ev.ViaName, ev.Confidence, ev.StartTime, ev.StopTime)
		if err != nil {
			log.Printf("[connector] upsert technique evidence %q/%s: %v", actorName, ev.TechniqueID, err)
		}
	}
}
