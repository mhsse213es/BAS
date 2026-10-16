package wafverify

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func mustBenchmarkScenario(t *testing.T) BenchmarkScenario {
	t.Helper()
	s, err := NewBenchmarkScenario("WAFVERIFY-002", "x", "y")
	if err != nil {
		t.Fatalf("NewBenchmarkScenario: %v", err)
	}
	return s
}

func TestNewBenchmarkScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewBenchmarkScenario("", "x", "y")
	if err == nil {
		t.Fatal("want error for empty id, got nil")
	}
}

func TestNewVendorResult_EmptyVendor_Rejected(t *testing.T) {
	_, err := NewVendorResult("", "v1", wafval.VerdictBlocked)
	if err == nil {
		t.Fatal("want error for empty vendor, got nil")
	}
}

func TestNewVendorResult_EmptyVersion_Rejected(t *testing.T) {
	_, err := NewVendorResult("VendorA", "", wafval.VerdictBlocked)
	if err == nil {
		t.Fatal("want error for empty version, got nil")
	}
}

func mustVendorResult(t *testing.T, vendor string, verdict wafval.Verdict) VendorResult {
	t.Helper()
	v, err := NewVendorResult(vendor, "v1", verdict)
	if err != nil {
		t.Fatalf("NewVendorResult: %v", err)
	}
	return v
}

func TestEvaluateBenchmark_AStronger_ReturnsStrongerAndNamesBothVendors(t *testing.T) {
	scenario := mustBenchmarkScenario(t)
	a := mustVendorResult(t, "VendorA", wafval.VerdictBlocked)
	b := mustVendorResult(t, "VendorB", wafval.VerdictMissed)
	outcome, reason, err := EvaluateBenchmark(scenario, a, b)
	if err != nil {
		t.Fatalf("EvaluateBenchmark: %v", err)
	}
	if outcome != BenchmarkStronger {
		t.Errorf("outcome = %q, want %q", outcome, BenchmarkStronger)
	}
	if !strings.Contains(reason, "VendorA") || !strings.Contains(reason, "VendorB") {
		t.Errorf("reason = %q, want it to name both VendorA and VendorB", reason)
	}
}

func TestEvaluateBenchmark_AWeaker_ReturnsWeaker(t *testing.T) {
	scenario := mustBenchmarkScenario(t)
	a := mustVendorResult(t, "VendorA", wafval.VerdictMissed)
	b := mustVendorResult(t, "VendorB", wafval.VerdictBlocked)
	outcome, _, err := EvaluateBenchmark(scenario, a, b)
	if err != nil {
		t.Fatalf("EvaluateBenchmark: %v", err)
	}
	if outcome != BenchmarkWeaker {
		t.Errorf("outcome = %q, want %q", outcome, BenchmarkWeaker)
	}
}

func TestEvaluateBenchmark_EqualRanks_ReturnsTied(t *testing.T) {
	scenario := mustBenchmarkScenario(t)
	a := mustVendorResult(t, "VendorA", wafval.VerdictBlocked)
	b := mustVendorResult(t, "VendorB", wafval.VerdictBlocked)
	outcome, _, err := EvaluateBenchmark(scenario, a, b)
	if err != nil {
		t.Fatalf("EvaluateBenchmark: %v", err)
	}
	if outcome != BenchmarkTied {
		t.Errorf("outcome = %q, want %q", outcome, BenchmarkTied)
	}
}

// Review Focus: an unrankable verdict on either side must trigger
// Inconclusive, not be silently ranked as 0.
func TestEvaluateBenchmark_AUnrankable_ReturnsInconclusive(t *testing.T) {
	scenario := mustBenchmarkScenario(t)
	a := mustVendorResult(t, "VendorA", wafval.VerdictAllowed)
	b := mustVendorResult(t, "VendorB", wafval.VerdictBlocked)
	outcome, _, err := EvaluateBenchmark(scenario, a, b)
	if err != nil {
		t.Fatalf("EvaluateBenchmark: %v", err)
	}
	if outcome != BenchmarkInconclusive {
		t.Errorf("outcome = %q, want %q", outcome, BenchmarkInconclusive)
	}
}
