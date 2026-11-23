package beaconperiod

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fixture struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	ExpectPeriodic bool     `json:"expect_periodic"`
	Timestamps     []string `json:"timestamps"`
}

func loadFixture(t *testing.T, path string) (fixture, []time.Time) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var fx fixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	times := make([]time.Time, 0, len(fx.Timestamps))
	for _, s := range fx.Timestamps {
		tm, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatalf("%s: bad timestamp %q: %v", path, s, err)
		}
		times = append(times, tm)
	}
	return fx, times
}

// TestRecordedFixtures runs every recorded fixture and checks the verdict it was recorded with.
func TestRecordedFixtures(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no fixtures found in testdata: %v", err)
	}
	for _, p := range paths {
		fx, times := loadFixture(t, p)
		t.Run(fx.Name, func(t *testing.T) {
			res := Analyze(times, Config{})
			if res.Periodic != fx.ExpectPeriodic {
				t.Fatalf("%s: Periodic=%v want %v (steady=%.3f median=%v events=%d reason=%q)",
					fx.Description, res.Periodic, fx.ExpectPeriodic, res.SteadyFraction, res.MedianInterval, res.Events, res.Reason)
			}
		})
	}
}

func TestMedianIntervalForFixedBeacon(t *testing.T) {
	_, times := loadFixture(t, filepath.Join("testdata", "beacon_fixed_60s.json"))
	res := Analyze(times, Config{})
	if res.MedianInterval != 60*time.Second {
		t.Fatalf("median = %v, want 60s", res.MedianInterval)
	}
	if res.SteadyFraction != 1 {
		t.Fatalf("steady fraction = %v, want 1", res.SteadyFraction)
	}
}

func TestTooFewEventsIsNeverPeriodic(t *testing.T) {
	base := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	var times []time.Time
	for i := 0; i < 7; i++ {
		times = append(times, base.Add(time.Duration(i)*time.Minute))
	}
	if res := Analyze(times, Config{}); res.Periodic {
		t.Fatalf("7 events must not establish a pattern under the default MinEvents=8: %+v", res)
	}
}

func TestInputOrderDoesNotMatter(t *testing.T) {
	_, times := loadFixture(t, filepath.Join("testdata", "beacon_fixed_60s.json"))
	reversed := make([]time.Time, len(times))
	for i, tm := range times {
		reversed[len(times)-1-i] = tm
	}
	if a, b := Analyze(times, Config{}), Analyze(reversed, Config{}); a.Periodic != b.Periodic || a.MedianInterval != b.MedianInterval {
		t.Fatalf("order changed the result: %+v vs %+v", a, b)
	}
}

func TestDuplicateTimestampsAreIgnoredNotCountedAsIntervals(t *testing.T) {
	base := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	var times []time.Time
	for i := 0; i < 10; i++ {
		tm := base.Add(time.Duration(i) * time.Minute)
		times = append(times, tm, tm) // every event logged twice
	}
	res := Analyze(times, Config{})
	if !res.Periodic || res.MedianInterval != time.Minute {
		t.Fatalf("duplicates should not hide a 60s beacon: %+v", res)
	}
}

func TestCustomThresholdCanTightenTheVerdict(t *testing.T) {
	_, times := loadFixture(t, filepath.Join("testdata", "beacon_with_dropped_events_300s.json"))
	strict := Config{MinSteadyFraction: 0.99}
	if res := Analyze(times, strict); res.Periodic {
		t.Fatalf("a 0.99 steady requirement should reject a beacon with dropped events: %+v", res)
	}
}
