// Package riskquant turns open exposures into an estimated annual loss range for the board.
//
// Every frequency and per-event magnitude is supplied by the customer. The package holds no
// default money figures and no default frequencies: an exposure without them is reported as
// not quantified, never as zero and never as a guess.
//
// Method: annualised loss expectancy (ALE) = event frequency per year x loss per event. Each
// exposure gives a low, likely and high ALE by multiplying the matching bounds. Totals sum the
// quantified exposures. This is a bounded range from the customer's inputs, not a statistical
// confidence interval, and it assumes exposures are independent.
package riskquant

import (
	"errors"
	"fmt"
	"math"
)

// Method and Limitations are carried in every Summary so the figure is never read without them.
const (
	Method      = "Annualised loss expectancy = event frequency per year x loss per event, computed for the low, likely and high bounds supplied by the customer. Totals sum the quantified exposures."
	Limitations = "Not a probability or a statistical confidence interval. Inputs are customer estimates; exposures are treated as independent, so totals can over- or under-state correlated losses. Unquantified exposures are excluded from totals and listed separately."
)

// Range is a low, likely and high estimate. Low <= Likely <= High, all finite and >= 0.
type Range struct {
	Low    float64
	Likely float64
	High   float64
}

// Exposure is one open gap to quantify. Frequency is events per year. Magnitude is currency per event.
// A nil Frequency or Magnitude means the customer has not supplied it, and the exposure is not quantified.
type Exposure struct {
	ID        string
	Label     string
	Frequency *Range
	Magnitude *Range
}

// Item is the result for one exposure.
type Item struct {
	ID         string
	Label      string
	Quantified bool
	// Frequency and Magnitude are the inputs this item was computed from; nil when not quantified.
	Frequency *Range
	Magnitude *Range
	ALE       Range
}

// Summary is the result for a set of exposures.
type Summary struct {
	Currency     string
	Items        []Item
	Total        Range
	Unquantified []string
	Method       string
	Limitations  string
}

// Compute validates the inputs and returns the per-exposure and total ALE. Invalid input is an error;
// it is never dropped silently.
func Compute(currency string, exposures []Exposure) (Summary, error) {
	if currency == "" {
		return Summary{}, errors.New("riskquant: currency is required")
	}
	s := Summary{Currency: currency, Method: Method, Limitations: Limitations}
	for _, e := range exposures {
		if e.ID == "" {
			return Summary{}, errors.New("riskquant: every exposure needs an ID")
		}
		it := Item{ID: e.ID, Label: e.Label}
		if e.Frequency == nil || e.Magnitude == nil {
			s.Unquantified = append(s.Unquantified, e.ID)
			s.Items = append(s.Items, it)
			continue
		}
		if err := ValidateRange(e.Frequency); err != nil {
			return Summary{}, fmt.Errorf("riskquant: %s frequency: %w", e.ID, err)
		}
		if err := ValidateRange(e.Magnitude); err != nil {
			return Summary{}, fmt.Errorf("riskquant: %s magnitude: %w", e.ID, err)
		}
		it.Quantified = true
		it.Frequency = copyRange(e.Frequency)
		it.Magnitude = copyRange(e.Magnitude)
		it.ALE = Range{
			Low:    e.Frequency.Low * e.Magnitude.Low,
			Likely: e.Frequency.Likely * e.Magnitude.Likely,
			High:   e.Frequency.High * e.Magnitude.High,
		}
		s.Total.Low += it.ALE.Low
		s.Total.Likely += it.ALE.Likely
		s.Total.High += it.ALE.High
		s.Items = append(s.Items, it)
	}
	return s, nil
}

func copyRange(r *Range) *Range {
	c := *r
	return &c
}

// ValidateRange reports whether a range is finite, non-negative and ordered low <= likely <= high.
func ValidateRange(r *Range) error {
	for _, v := range []float64{r.Low, r.Likely, r.High} {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return errors.New("must be finite")
		}
		if v < 0 {
			return errors.New("must not be negative")
		}
	}
	if !(r.Low <= r.Likely && r.Likely <= r.High) {
		return errors.New("bounds must satisfy low <= likely <= high")
	}
	return nil
}
