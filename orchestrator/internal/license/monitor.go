package license

import (
	"context"
	"log"
	"sync/atomic"
	"time"
)

var current atomic.Value // holds Info

// SetInitial seeds the state atomic.Value read by Current, synchronously,
// before StartMonitor's ticker begins. Call once, at startup, right after
// the first Evaluate — guarantees Current() never reads a zero-valued Info
// once the caller has started up (an unseeded Current() before this is
// ever called returns a zero-value Info{} whose State is "", which every
// enforcement point in this codebase treats as "not locked" — fail-open
// by construction, never fail-closed on a forgotten seed).
func SetInitial(info Info) {
	current.Store(info)
}

// Current returns the most recently stored evaluation (from SetInitial
// until the first tick, from the ticker thereafter).
func Current() Info {
	v := current.Load()
	if v == nil {
		return Info{}
	}
	return v.(Info)
}

// StartMonitor begins a background ticker that re-parses and re-evaluates
// the license at licPath every interval, overwriting the value SetInitial
// seeded. onLock is called at most once per transition into StateLocked
// (nil-safe — pass nil to skip). Stops when ctx is cancelled.
func StartMonitor(ctx context.Context, licPath string, interval time.Duration, onLock func()) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		wasLocked := Current().State == StateLocked
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				lic, err := Get(licPath)
				if err != nil {
					log.Printf("[license] monitor: re-read failed: %v (keeping last known state)", err)
					continue
				}
				info, err := Evaluate(lic, time.Now().UTC())
				if err != nil {
					log.Printf("[license] monitor: re-evaluate failed: %v (keeping last known state)", err)
					continue
				}
				current.Store(info)
				nowLocked := info.State == StateLocked
				if nowLocked && !wasLocked && onLock != nil {
					onLock()
				}
				wasLocked = nowLocked
			}
		}
	}()
}
