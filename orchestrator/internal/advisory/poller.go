package advisory

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

// Fetcher pulls the current advisories from one source. Implementations live
// outside this package and are wired only once their payload has been verified
// against a real feed item.
type Fetcher interface {
	Source() string // "cert_in" or "fs_isac"
	Fetch(ctx context.Context) ([]Item, error)
}

// PollerConfig controls the poller. The zero value is dormant: it fetches nothing.
type PollerConfig struct {
	// Enabled must be set true explicitly. Off means Run returns at once and
	// no fetcher is ever called.
	Enabled  bool
	Interval time.Duration
}

// ErrNoFetchers is returned when polling is enabled but no verified fetcher is wired.
// Enabling without a fetcher fails closed rather than polling nothing silently.
var ErrNoFetchers = errors.New("advisory: polling enabled but no verified fetcher is configured")

// Poller runs fetch-and-intake cycles for the configured fetchers.
type Poller struct {
	cfg      PollerConfig
	store    *Store
	fetchers []Fetcher
}

// NewPoller validates the config. It does not start anything.
func NewPoller(cfg PollerConfig, store *Store, fetchers ...Fetcher) (*Poller, error) {
	if store == nil {
		return nil, errors.New("advisory: poller needs a store")
	}
	if cfg.Enabled {
		if len(fetchers) == 0 {
			return nil, ErrNoFetchers
		}
		if cfg.Interval < time.Minute {
			return nil, fmt.Errorf("advisory: poll interval %s is below the one-minute floor", cfg.Interval)
		}
	}
	return &Poller{cfg: cfg, store: store, fetchers: fetchers}, nil
}

// Tick runs one cycle over every fetcher. A failing source is logged and
// skipped so the others still run. The returned error joins the failures.
func (p *Poller) Tick(ctx context.Context) (IntakeResult, error) {
	var total IntakeResult
	var errs []error
	for _, f := range p.fetchers {
		items, err := f.Fetch(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.Source(), err))
			log.Printf("[advisory] %s fetch failed: %v", f.Source(), err)
			continue
		}
		res, err := p.store.Intake(ctx, items)
		total.Inserted += res.Inserted
		total.Duplicates += res.Duplicates
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.Source(), err))
		}
	}
	return total, errors.Join(errs...)
}

// Run ticks on the interval until ctx is done. When polling is disabled it
// returns immediately, so a dormant poller costs nothing and touches no network.
func (p *Poller) Run(ctx context.Context) {
	if !p.cfg.Enabled {
		return
	}
	t := time.NewTicker(p.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := p.Tick(ctx); err != nil {
				log.Printf("[advisory] poll cycle: %v", err)
			}
		}
	}
}
