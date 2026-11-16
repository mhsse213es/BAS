package scenario

import (
	"path/filepath"
	"strings"
	"testing"
)

// windows-discovery-validation is detection-only: every step is a telemetry probe with no prevention verdict, so each
// must resolve expectations (a Defender one the host can resolve, a SIEM one an analyst or connector can answer), and
// the description must tell the truth about how it is graded.
func TestWindowsDiscoveryValidation_IsGradedOnDetection(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "scenarios"))
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(dir)
	if err := e.Load(); err != nil {
		t.Fatalf("engine load: %v", err)
	}
	sc, ok := e.Get("windows-discovery-validation")
	if !ok {
		t.Fatal("scenario did not load (signature stale?)")
	}
	if _, ok := e.Profiles()["windows_remote_system_discovery"]; !ok {
		t.Fatal("the T1018 detection profile did not load (signature missing?)")
	}
	if len(sc.Steps) != 3 {
		t.Fatalf("steps = %d, want 3", len(sc.Steps))
	}
	for _, step := range sc.Steps {
		exps, _ := e.ResolveStepExpectations(step)
		var edr, siem bool
		for _, x := range exps {
			switch ResolveDomain(x) {
			case DomainEndpoint:
				edr = true
			case DomainSIEM:
				siem = ResolveVerification(x) != VerificationAutomatic
			}
		}
		if !edr || !siem {
			t.Errorf("%s: expectations resolved edr=%v siem=%v, want both (got %d)", step.TechniqueID, edr, siem, len(exps))
		}
	}
	d := strings.ToLower(sc.Description)
	for _, want := range []string{"detection-only", "not assessed", "detection gap"} {
		if !strings.Contains(d, want) {
			t.Errorf("description should explain grading, missing %q", want)
		}
	}
	if strings.Contains(sc.Description, "PASS  = EDR/SIEM detected") {
		t.Error("the old PASS/FAIL legend no longer applies to this scenario")
	}
}
