package taxii

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/exercise"
)

const defaultPollInterval = 24 * time.Hour

// Manager owns one Poller + one exercise.PollScheduler per currently-enabled
// ConnectorConfig row. Deliberately separate from internal/connector.Scheduler
// (see spec's Sync wiring section) -- TAXII configs are independently
// enabled/disabled/deleted at runtime, which a single shared Source-list
// scheduler doesn't model.
type Manager struct {
	pool       *pgxpool.Pool
	store      *Store
	normalizer *Normalizer

	mu         sync.Mutex
	schedulers map[string]*exercise.PollScheduler // connector id -> its scheduler
}

func NewManager(pool *pgxpool.Pool, store *Store) *Manager {
	return &Manager{
		pool: pool, store: store, normalizer: NewNormalizer(pool, store),
		schedulers: map[string]*exercise.PollScheduler{},
	}
}

// Start launches one scheduler per currently-enabled config row. Each
// scheduler fires an immediate Sync in a goroutine on start (matching
// connector.Scheduler.Start's "run immediately on startup" precedent) --
// exercise.PollScheduler.Start itself only fires after a full interval
// elapses, which would otherwise mean a 24h wait before a freshly-enabled
// connector's first sync.
func (m *Manager) Start(ctx context.Context) error {
	cfgs, err := m.store.ListEnabled(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, cfg := range cfgs {
		m.startLocked(cfg)
	}
	return nil
}

func (m *Manager) startLocked(cfg ConnectorConfig) {
	poller := NewPoller(cfg, m.store, m.normalizer)
	sched := exercise.NewPollScheduler(defaultPollInterval)
	sched.Start(func(ctx context.Context) {
		if err := poller.Sync(ctx); err != nil {
			log.Printf("[taxii] sync failed for connector %s (%s): %v", cfg.ID, cfg.Name, err)
		}
	})
	m.schedulers[cfg.ID] = sched
	go func() {
		if err := poller.Sync(context.Background()); err != nil {
			log.Printf("[taxii] initial sync failed for connector %s (%s): %v", cfg.ID, cfg.Name, err)
		}
	}()
}

// Reconcile fully restarts the running scheduler set to match current DB
// state -- called after every config create/update/delete/enable-toggle.
// A full stop-and-restart (rather than a diff-and-patch) is deliberately
// simple: it's the only way to guarantee an edited server_url/credentials
// change takes effect immediately rather than waiting inside a stale
// closure until the next natural restart, and this only runs on rare admin
// actions, not a hot path.
func (m *Manager) Reconcile(ctx context.Context) error {
	cfgs, err := m.store.ListEnabled(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, sched := range m.schedulers {
		sched.Stop()
		delete(m.schedulers, id)
	}
	for _, cfg := range cfgs {
		m.startLocked(cfg)
	}
	return nil
}

// TriggerSync runs one immediate Sync for a single connector, outside its
// regular interval -- used by the manual "Sync Now" API. Works even for a
// disabled connector (an admin validating before enabling).
func (m *Manager) TriggerSync(ctx context.Context, connectorID string) error {
	cfg, err := m.store.Get(ctx, connectorID)
	if err != nil {
		return err
	}
	poller := NewPoller(cfg, m.store, m.normalizer)
	return poller.Sync(ctx)
}

// Stop shuts down every running scheduler.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sched := range m.schedulers {
		sched.Stop()
	}
}
