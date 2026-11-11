package riskquant

import (
	"math"
	"testing"
)

func rng(l, m, h float64) *Range { return &Range{Low: l, Likely: m, High: h} }

func near(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

// Annualised loss is frequency times per-event magnitude, computed per bound.
func TestComputeMultipliesBoundsPerExposure(t *testing.T) {
	s, err := Compute("USD", []Exposure{{
		ID: "T1003", Label: "Credential dumping",
		Frequency: rng(1, 2, 4),
		Magnitude: rng(10000, 50000, 200000),
	}})
	if err != nil {
		t.Fatal(err)
	}
	r := s.Items[0]
	if !r.Quantified {
		t.Fatalf("expected quantified, got %+v", r)
	}
	if !near(r.ALE.Low, 10000) || !near(r.ALE.Likely, 100000) || !near(r.ALE.High, 800000) {
		t.Errorf("ALE = %+v, want {10000 100000 800000}", r.ALE)
	}
}

// Totals are the sum of the quantified exposures; unquantified ones are listed, not counted as zero.
func TestTotalSumsQuantifiedAndListsUnquantified(t *testing.T) {
	s, err := Compute("EUR", []Exposure{
		{ID: "T1", Frequency: rng(1, 1, 1), Magnitude: rng(100, 100, 100)},
		{ID: "T2", Frequency: rng(2, 2, 2), Magnitude: rng(50, 50, 50)},
		{ID: "T3", Frequency: nil, Magnitude: rng(10, 10, 10)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !near(s.Total.Likely, 200) {
		t.Errorf("total likely = %v, want 200", s.Total.Likely)
	}
	if len(s.Unquantified) != 1 || s.Unquantified[0] != "T3" {
		t.Errorf("unquantified = %v, want [T3]", s.Unquantified)
	}
	if s.Items[2].Quantified {
		t.Error("T3 has no frequency and must not be quantified")
	}
}

// Missing currency, negative or unordered ranges, and non-finite numbers are errors, never silently dropped.
func TestRejectsInvalidInput(t *testing.T) {
	cases := map[string][]Exposure{
		"negative":  {{ID: "x", Frequency: rng(-1, 1, 2), Magnitude: rng(1, 1, 1)}},
		"unordered": {{ID: "x", Frequency: rng(3, 2, 4), Magnitude: rng(1, 1, 1)}},
		"nan":       {{ID: "x", Frequency: rng(math.NaN(), 1, 2), Magnitude: rng(1, 1, 1)}},
		"inf":       {{ID: "x", Frequency: rng(1, 1, math.Inf(1)), Magnitude: rng(1, 1, 1)}},
		"empty id":  {{ID: "", Frequency: rng(1, 1, 1), Magnitude: rng(1, 1, 1)}},
	}
	for name, ex := range cases {
		if _, err := Compute("USD", ex); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := Compute("", []Exposure{{ID: "x", Frequency: rng(1, 1, 1), Magnitude: rng(1, 1, 1)}}); err == nil {
		t.Error("empty currency: expected an error")
	}
}

// Zero frequency is a real answer ("never happens"), distinct from an unquantified exposure.
func TestZeroFrequencyIsQuantifiedAsZero(t *testing.T) {
	s, err := Compute("USD", []Exposure{{ID: "T9", Frequency: rng(0, 0, 0), Magnitude: rng(5000, 5000, 5000)}})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Items[0].Quantified || s.Items[0].ALE.High != 0 {
		t.Errorf("zero frequency should quantify to 0, got %+v", s.Items[0])
	}
}

// The result must say what the figure is not, so no one reads it as a probability or a confidence interval.
func TestStatementStatesLimits(t *testing.T) {
	s, _ := Compute("USD", nil)
	if s.Method == "" || s.Limitations == "" {
		t.Error("summary must carry the method and its limitations")
	}
}

// Each item carries the inputs it was computed from, so a signed report can show them.
func TestItemsCarryTheirInputs(t *testing.T) {
	f := rng(1, 2, 4)
	m := rng(10, 20, 30)
	s, err := Compute("USD", []Exposure{{ID: "T1", Frequency: f, Magnitude: m}, {ID: "T2"}})
	if err != nil {
		t.Fatal(err)
	}
	if s.Items[0].Frequency == nil || *s.Items[0].Frequency != *f || *s.Items[0].Magnitude != *m {
		t.Errorf("quantified item must carry its inputs, got %+v", s.Items[0])
	}
	if s.Items[1].Frequency != nil || s.Items[1].Magnitude != nil {
		t.Errorf("unquantified item must carry no inputs, got %+v", s.Items[1])
	}
}
