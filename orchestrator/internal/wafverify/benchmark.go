package wafverify

import (
	"fmt"

	"github.com/audspect/bas/internal/wafval"
)

// BenchmarkScenario is the claim that two vendors' or versions' verdicts
// for the same scenario can be ranked against each other.
type BenchmarkScenario struct {
	ID          string
	Description string
	Provenance  string
}

// NewBenchmarkScenario validates at construction time, never at render
// time.
func NewBenchmarkScenario(id string, description string, provenance string) (BenchmarkScenario, error) {
	if id == "" {
		return BenchmarkScenario{}, fmt.Errorf("id must not be empty")
	}
	if description == "" {
		return BenchmarkScenario{}, fmt.Errorf("description must not be empty")
	}
	if provenance == "" {
		return BenchmarkScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return BenchmarkScenario{ID: id, Description: description, Provenance: provenance}, nil
}

// VendorResult is one vendor's/version's verdict for a benchmark
// comparison.
type VendorResult struct {
	Vendor  string
	Version string
	Verdict wafval.Verdict
}

// NewVendorResult validates at construction time, never at render time.
func NewVendorResult(vendor string, version string, verdict wafval.Verdict) (VendorResult, error) {
	if vendor == "" {
		return VendorResult{}, fmt.Errorf("vendor must not be empty")
	}
	if version == "" {
		return VendorResult{}, fmt.Errorf("version must not be empty")
	}
	return VendorResult{Vendor: vendor, Version: version, Verdict: verdict}, nil
}

// BenchmarkOutcome is the outcome of comparing two VendorResults for the
// same scenario. Stronger/Weaker describe a relative to b.
type BenchmarkOutcome string

const (
	BenchmarkStronger     BenchmarkOutcome = "stronger"
	BenchmarkWeaker       BenchmarkOutcome = "weaker"
	BenchmarkTied         BenchmarkOutcome = "tied"
	BenchmarkInconclusive BenchmarkOutcome = "inconclusive"
)

// EvaluateBenchmark ranks both VendorResults' verdicts; either side
// unrankable resolves to BenchmarkInconclusive rather than guessing a
// direction.
func EvaluateBenchmark(scenario BenchmarkScenario, a VendorResult, b VendorResult) (BenchmarkOutcome, string, error) {
	aRank, aOK := verdictRank(a.Verdict)
	bRank, bOK := verdictRank(b.Verdict)
	if !aOK || !bOK {
		return BenchmarkInconclusive, fmt.Sprintf("%s %s's verdict %q or %s %s's verdict %q is not a ClaimPrevention-shaped verdict this comparison can rank", a.Vendor, a.Version, a.Verdict, b.Vendor, b.Version, b.Verdict), nil
	}
	switch {
	case aRank > bRank:
		return BenchmarkStronger, fmt.Sprintf("%s %s (%q) ranks above %s %s (%q)", a.Vendor, a.Version, a.Verdict, b.Vendor, b.Version, b.Verdict), nil
	case aRank < bRank:
		return BenchmarkWeaker, fmt.Sprintf("%s %s (%q) ranks below %s %s (%q)", a.Vendor, a.Version, a.Verdict, b.Vendor, b.Version, b.Verdict), nil
	default:
		return BenchmarkTied, fmt.Sprintf("%s %s (%q) ranks equal to %s %s (%q)", a.Vendor, a.Version, a.Verdict, b.Vendor, b.Version, b.Verdict), nil
	}
}
