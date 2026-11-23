// Package beaconperiod decides whether a series of event timestamps repeats at a steady interval, the
// signature of a periodic C2-style beacon. It is a pure function: it reads timestamps and returns a verdict.
// It does not query telemetry and is not wired into product detection.
package beaconperiod

import (
	"math"
	"sort"
	"time"
)

// Config holds the thresholds. Zero values are replaced by the defaults in DefaultConfig.
type Config struct {
	// MinEvents is the fewest timestamps that can establish a pattern (events, not intervals).
	MinEvents int
	// Tolerance is how far an interval may sit from the median interval and still count as steady (0.15 = ±15%).
	Tolerance float64
	// MinSteadyFraction is the share of intervals that must be steady. It is below 1 so that a few
	// dropped or delayed events do not hide a real beacon.
	MinSteadyFraction float64
}

// DefaultConfig is the release threshold.
func DefaultConfig() Config {
	return Config{MinEvents: 8, Tolerance: 0.15, MinSteadyFraction: 0.80}
}

// Result is the analyzer output. Periodic is true only when every threshold is met.
type Result struct {
	Periodic       bool
	Events         int
	MedianInterval time.Duration
	SteadyFraction float64
	Reason         string
}

// Analyze sorts the timestamps and reports whether the intervals between them are steady.
func Analyze(times []time.Time, cfg Config) Result {
	d := DefaultConfig()
	if cfg.MinEvents == 0 {
		cfg.MinEvents = d.MinEvents
	}
	if cfg.Tolerance == 0 {
		cfg.Tolerance = d.Tolerance
	}
	if cfg.MinSteadyFraction == 0 {
		cfg.MinSteadyFraction = d.MinSteadyFraction
	}
	res := Result{Events: len(times)}
	if len(times) < cfg.MinEvents {
		res.Reason = "too few events to establish a pattern"
		return res
	}
	ts := append([]time.Time(nil), times...)
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })

	intervals := make([]float64, 0, len(ts)-1)
	for i := 1; i < len(ts); i++ {
		gap := ts[i].Sub(ts[i-1]).Seconds()
		if gap <= 0 {
			continue // duplicate timestamps carry no interval information
		}
		intervals = append(intervals, gap)
	}
	if len(intervals) < cfg.MinEvents-1 {
		res.Reason = "too few distinct intervals to establish a pattern"
		return res
	}

	sorted := append([]float64(nil), intervals...)
	sort.Float64s(sorted)
	median := sorted[len(sorted)/2]
	if len(sorted)%2 == 0 {
		median = (sorted[len(sorted)/2-1] + sorted[len(sorted)/2]) / 2
	}
	res.MedianInterval = time.Duration(median * float64(time.Second))

	steady := 0
	lo, hi := median*(1-cfg.Tolerance), median*(1+cfg.Tolerance)
	for _, g := range intervals {
		if g >= lo && g <= hi {
			steady++
		}
	}
	res.SteadyFraction = math.Round(float64(steady)/float64(len(intervals))*1000) / 1000
	if res.SteadyFraction >= cfg.MinSteadyFraction {
		res.Periodic = true
		res.Reason = "intervals repeat at a steady period"
	} else {
		res.Reason = "intervals are not steady enough to be periodic"
	}
	return res
}
