package connector

import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/audspect/bas/internal/scenario"
)

// Scheduler polls MISP and OpenCTI on a configurable interval and
// regenerates intel scenarios into the scenarios/intel/ directory.
type Scheduler struct {
	misp      *MISPClient
	opencti   *OpenCTIClient
	generator *Generator
	engine    *scenario.Engine
	interval  time.Duration

	mu        sync.RWMutex
	status    ConnectorStatus
	syncCh    chan struct{} // manual trigger
	stopCh    chan struct{}
}

// NewScheduler creates a Scheduler. Pass nil for either client to disable it.
func NewScheduler(
	misp *MISPClient,
	opencti *OpenCTIClient,
	generator *Generator,
	engine *scenario.Engine,
	pollHours int,
) *Scheduler {
	if pollHours <= 0 {
		pollHours = 24
	}
	s := &Scheduler{
		misp:      misp,
		opencti:   opencti,
		generator: generator,
		engine:    engine,
		interval:  time.Duration(pollHours) * time.Hour,
		syncCh:    make(chan struct{}, 1),
		stopCh:    make(chan struct{}),
	}
	s.status = ConnectorStatus{
		MISPEnabled:    misp != nil,
		OpenCTIEnabled: opencti != nil,
		LastSyncStatus: "never",
		NextSyncAt:     time.Now().Add(s.interval),
	}
	return s
}

// Start launches the background polling goroutine.
func (s *Scheduler) Start() {
	if s.misp == nil && s.opencti == nil {
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

	// ── MISP ──────────────────────────────────────────────────────────────
	if s.misp != nil {
		mActors, err := s.misp.Fetch()
		if err != nil {
			log.Printf("[connector/misp] fetch error: %v", err)
			s.setError("MISP: " + err.Error())
		} else {
			log.Printf("[connector/misp] %d actors fetched", len(mActors))
			actors = append(actors, mActors...)
		}
	}

	// ── OpenCTI ───────────────────────────────────────────────────────────
	if s.opencti != nil {
		oActors, err := s.opencti.Fetch()
		if err != nil {
			log.Printf("[connector/opencti] fetch error: %v", err)
			s.setError("OpenCTI: " + err.Error())
		} else {
			log.Printf("[connector/opencti] %d actors fetched", len(oActors))
			actors = append(actors, oActors...)
		}
	}

	if len(actors) == 0 {
		log.Println("[connector] no actors returned from any source")
		s.setOK(0, 0, 0)
		return
	}

	// Merge actors with the same name from different sources
	actors = mergeActors(actors)

	// ── Generate scenarios ────────────────────────────────────────────────
	result, err := s.generator.Write(actors)
	if err != nil {
		log.Printf("[connector/gen] write error: %v", err)
		s.setError("Generator: " + err.Error())
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

	s.setOK(result.Created, result.Updated, len(actors))
}

func (s *Scheduler) setOK(created, updated, total int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.LastSyncAt = time.Now()
	s.status.LastSyncStatus = "ok"
	s.status.LastError = ""
	s.status.ScenariosCreated += created
	s.status.ScenariosUpdated += updated
	s.status.TotalActors = total
	s.status.NextSyncAt = time.Now().Add(s.interval)
}

func (s *Scheduler) setError(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.LastSyncAt = time.Now()
	s.status.LastSyncStatus = "error"
	s.status.LastError = msg
	s.status.NextSyncAt = time.Now().Add(s.interval)
}

// mergeActors combines actors with the same name (case-insensitive) from
// different sources into one actor with the union of their techniques.
func mergeActors(actors []ThreatActor) []ThreatActor {
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
