package jobs

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeLister struct {
	windows []Blackout
	err     error
}

func (f fakeLister) ListBlackouts(context.Context) ([]Blackout, error) { return f.windows, f.err }

func dailyWindow() Blackout {
	return Blackout{ID: "w1", Name: "EoD batch", Kind: "daily", TimeFrom: "18:00", TimeTo: "23:00", Timezone: "UTC"}
}

// Automatic starters other than scheduled assessments (collection, sweeps, API BAS schedules, revalidation) wait while
// a change-freeze window covers the moment, and start again once it ends.
func TestHoldForFreeze(t *testing.T) {
	at := func(s string) time.Time { return mustTime(t, s) }
	cases := []struct {
		name string
		l    blackoutLister
		now  time.Time
		want bool
	}{
		{"inside a window", fakeLister{windows: []Blackout{dailyWindow()}}, at("2026-12-01T19:00:00Z"), true},
		{"outside every window", fakeLister{windows: []Blackout{dailyWindow()}}, at("2026-12-01T12:00:00Z"), false},
		{"no windows at all", fakeLister{}, at("2026-12-01T19:00:00Z"), false},
		{"windows unreadable: fail closed", fakeLister{err: errors.New("db down")}, at("2026-12-01T12:00:00Z"), true},
		{"no store wired: nothing to enforce", nil, at("2026-12-01T19:00:00Z"), false},
	}
	for _, c := range cases {
		if got := holdForFreeze(context.Background(), c.l, "test starter", c.now); got != c.want {
			t.Errorf("%s: held = %v, want %v", c.name, got, c.want)
		}
	}
}

// A nil *Store must not be mistaken for a wired one: callers pass whatever they were given.
func TestHoldForFreeze_NilStoreDoesNotPanicOrHold(t *testing.T) {
	var s *Store
	if HoldForFreeze(context.Background(), s, "test starter", time.Now()) {
		t.Fatal("a nil store held a starter")
	}
}
