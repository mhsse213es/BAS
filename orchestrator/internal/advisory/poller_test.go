package advisory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// countingFetcher records calls, so a test can prove a dormant poller never fetched.
type countingFetcher struct {
	source string
	items  []Item
	err    error
	calls  int
}

func (f *countingFetcher) Source() string { return f.source }
func (f *countingFetcher) Fetch(context.Context) ([]Item, error) {
	f.calls++
	return f.items, f.err
}

func TestDormantPollerNeverFetches(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		f := &countingFetcher{source: "cert_in", items: []Item{{Source: "cert_in", ExternalID: "DORM-1", Title: "t", SourceRef: "r"}}}
		p, err := NewPoller(PollerConfig{Enabled: false}, NewStore(pool), f)
		if err != nil {
			t.Fatalf("dormant poller rejected: %v", err)
		}
		// Run must return at once without a fetch.
		done := make(chan struct{})
		go func() { p.Run(context.Background()); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("dormant Run did not return")
		}
		if f.calls != 0 {
			t.Fatalf("dormant poller called the fetcher %d times", f.calls)
		}
	})
}

func TestEnabledPollerWithoutFetcherFailsClosed(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := NewPoller(PollerConfig{Enabled: true, Interval: time.Hour}, NewStore(pool))
		if !errors.Is(err, ErrNoFetchers) {
			t.Fatalf("enabled with no fetcher: %v, want ErrNoFetchers", err)
		}
	})
}

func TestEnabledPollerRejectsIntervalBelowFloor(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		f := &countingFetcher{source: "fs_isac"}
		if _, err := NewPoller(PollerConfig{Enabled: true, Interval: time.Second}, NewStore(pool), f); err == nil {
			t.Fatal("interval below one minute accepted")
		}
	})
}

func TestTickIntakesAndSkipsFailingSource(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		good := &countingFetcher{source: "fs_isac", items: []Item{
			{Source: "fs_isac", ExternalID: "TICK-1", Title: "t", SourceRef: "r"},
		}}
		bad := &countingFetcher{source: "cert_in", err: errors.New("feed unreachable")}
		p, err := NewPoller(PollerConfig{Enabled: true, Interval: time.Hour}, NewStore(pool), bad, good)
		if err != nil {
			t.Fatalf("new poller: %v", err)
		}
		res, err := p.Tick(context.Background())
		if err == nil {
			t.Fatal("failing source not reported")
		}
		if res.Inserted != 1 {
			t.Fatalf("good source not ingested despite the other failing: %+v", res)
		}
		// A second tick re-polls the same advisory: it is a duplicate, not a new row.
		again, _ := p.Tick(context.Background())
		if again.Inserted != 0 || again.Duplicates != 1 {
			t.Fatalf("re-poll = %+v; want one duplicate", again)
		}
	})
}
