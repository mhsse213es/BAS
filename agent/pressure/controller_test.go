package pressure

import "testing"

func TestController_SustainedHighEscalatesToHigh(t *testing.T) {
	c := NewController()
	var lvl Level
	for i := 0; i < 5; i++ {
		lvl = c.Observe(85, 10)
	}
	if lvl != LevelHigh {
		t.Fatalf("after sustained samples at 85%% CPU, level = %v, want %v", lvl, LevelHigh)
	}
}

func TestController_TransientSpikeDoesNotEscalate(t *testing.T) {
	c := NewController()
	for i := 0; i < 5; i++ {
		c.Observe(20, 10) // establish a low, stable baseline
	}
	// One single spike to 95%. EWMA at alpha=0.3 from a baseline of 20 moves
	// to 0.3*95 + 0.7*20 = 42.5 -- nowhere near the 80 escalate threshold.
	lvl := c.Observe(95, 10)
	if lvl != LevelNormal {
		t.Fatalf("after one transient spike, level = %v, want %v (EWMA must absorb a single noisy sample)", lvl, LevelNormal)
	}
}

func TestController_CrossingNinetyEscalatesToCritical(t *testing.T) {
	c := NewController()
	var lvl Level
	for i := 0; i < 5; i++ {
		lvl = c.Observe(95, 10)
	}
	if lvl != LevelCritical {
		t.Fatalf("after sustained samples at 95%% CPU, level = %v, want %v", lvl, LevelCritical)
	}
}

func TestController_DeadZoneHoldsCurrentLevel(t *testing.T) {
	c := NewController()
	for i := 0; i < 5; i++ {
		c.Observe(85, 10) // drive into High; EWMA converges to 85 immediately (constant input)
	}
	// Next sample of 35 moves the EWMA to 0.3*35 + 0.7*85 = 70.0 -- squarely
	// inside the 60-80 dead zone. This must hold High, not revert to Normal
	// just because 70 is below the escalate-high threshold.
	lvl := c.Observe(35, 10)
	if lvl != LevelHigh {
		t.Fatalf("dead-zone sample (EWMA lands at 70%%) changed level to %v, want it to hold %v", lvl, LevelHigh)
	}
}

func TestController_MemoryOnlySpikeEscalatesViaWorstWins(t *testing.T) {
	c := NewController()
	var lvl Level
	// CPU stays low throughout; only memory is high. If dimensions were
	// averaged instead of worst-wins, (10+95)/2 = 52.5 would never escalate.
	for i := 0; i < 5; i++ {
		lvl = c.Observe(10, 95)
	}
	if lvl != LevelCritical {
		t.Fatalf("sustained memory-only pressure: level = %v, want %v (worst-wins must not be diluted by low CPU)", lvl, LevelCritical)
	}
}

func TestController_ColdStartDoesNotFakeADip(t *testing.T) {
	c := NewController()
	// The very first Observe call must seed the EWMA directly from the
	// sample, not from a fake zero baseline. A first sample at 95% must
	// register as Critical immediately, not as diluted/smoothed-from-zero.
	lvl := c.Observe(95, 10)
	if lvl != LevelCritical {
		t.Fatalf("first-ever Observe call at 95%% reported %v, want %v -- cold start is diluting the first real sample as if smoothed from zero", lvl, LevelCritical)
	}
}

func TestController_RecoversToNormalBelowSixty(t *testing.T) {
	c := NewController()
	for i := 0; i < 5; i++ {
		c.Observe(95, 10) // drive into Critical
	}
	var lvl Level
	// Repeated low samples so the EWMA genuinely drops below 60, not just one
	// sample partway there.
	for i := 0; i < 5; i++ {
		lvl = c.Observe(10, 10)
	}
	if lvl != LevelNormal {
		t.Fatalf("after sustained low samples, level = %v, want %v (must recover from Critical straight to Normal)", lvl, LevelNormal)
	}
}

func TestLevel_String(t *testing.T) {
	cases := map[Level]string{LevelNormal: "normal", LevelHigh: "high", LevelCritical: "critical"}
	for level, want := range cases {
		if got := level.String(); got != want {
			t.Errorf("Level(%d).String() = %q, want %q", level, got, want)
		}
	}
}
