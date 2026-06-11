package models

import (
	"strings"
	"testing"
)

// A technique whose tactic default is misleading must get its technique-specific
// remediation. T1569.002 abuses service DACLs — the guidance must be about
// service-permission hardening, NOT PowerShell script-block logging (the
// "execution" tactic default the report wrongly emitted).
func TestRemediationTechniqueOverride(t *testing.T) {
	got := Remediation(ResultFail, "execution", "t1569.002", "Service Execution")
	low := strings.ToLower(got)
	if !strings.Contains(low, "dacl") && !strings.Contains(low, "service") {
		t.Errorf("T1569.002 remediation = %q, want service/DACL guidance", got)
	}
	if strings.Contains(low, "script block logging") || strings.Contains(low, "constrained language") {
		t.Errorf("T1569.002 remediation wrongly returned the execution-tactic default: %q", got)
	}
}

// A technique with no override falls back to the tactic-level default.
func TestRemediationFallsBackToTactic(t *testing.T) {
	got := Remediation(ResultFail, "credential-access", "T1003.001", "LSASS Memory")
	if !strings.Contains(strings.ToLower(got), "lsa protection") {
		t.Errorf("credential-access remediation = %q, want the tactic default", got)
	}
}

// A passed/blocked check never returns attack remediation.
func TestRemediationBlockedNoGuidance(t *testing.T) {
	got := Remediation(ResultPass, "execution", "T1569.002", "Service Execution")
	if !strings.Contains(strings.ToLower(got), "control validated") {
		t.Errorf("blocked remediation = %q, want validation message", got)
	}
}
