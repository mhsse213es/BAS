package avval

import (
	"fmt"
	"strings"
)

// ConfigurationSnapshot is what a policy/configuration check actually
// observed on the endpoint at test time -- distinct from an Observation,
// since it is a point-in-time state read, not evidence about a specific
// test execution.
type ConfigurationSnapshot struct {
	RealTimeProtectionEnabled bool
	CloudProtectionEnabled    bool
	TamperProtectionEnabled   bool
	SignatureAgeHours         int
	Exclusions                []string
	Coverage                  Coverage
}

// ConfigurationBaseline is the expected-compliant state a snapshot is graded
// against.
type ConfigurationBaseline struct {
	RequireRealTimeProtection bool
	RequireCloudProtection    bool
	RequireTamperProtection   bool
	MaxSignatureAgeHours      int
	DisallowedExclusions      []string
}

// EvaluateConfigurationSnapshot grades snapshot against baseline. It never
// infers compliance from an unavailable snapshot -- an unreadable
// configuration state is Unknown, never silently Compliant (fail closed,
// per av.txt §7).
func EvaluateConfigurationSnapshot(snapshot ConfigurationSnapshot, baseline ConfigurationBaseline) (ConfigurationState, string) {
	if !snapshot.Coverage.Present() {
		return ConfigurationUnknown, "configuration state could not be read"
	}
	var gaps []string
	if baseline.RequireRealTimeProtection && !snapshot.RealTimeProtectionEnabled {
		gaps = append(gaps, "real-time protection disabled")
	}
	if baseline.RequireCloudProtection && !snapshot.CloudProtectionEnabled {
		gaps = append(gaps, "cloud protection disabled")
	}
	if baseline.RequireTamperProtection && !snapshot.TamperProtectionEnabled {
		gaps = append(gaps, "tamper protection disabled")
	}
	if baseline.MaxSignatureAgeHours > 0 && snapshot.SignatureAgeHours > baseline.MaxSignatureAgeHours {
		gaps = append(gaps, fmt.Sprintf("signatures are %dh old, exceeding the %dh baseline", snapshot.SignatureAgeHours, baseline.MaxSignatureAgeHours))
	}
	disallowed := make(map[string]bool, len(baseline.DisallowedExclusions))
	for _, d := range baseline.DisallowedExclusions {
		disallowed[d] = true
	}
	for _, actual := range snapshot.Exclusions {
		if disallowed[actual] {
			gaps = append(gaps, "disallowed exclusion present: "+actual)
		}
	}
	if len(gaps) == 0 {
		return ConfigurationCompliant, "configuration matches the required baseline"
	}
	return ConfigurationPolicyGap, strings.Join(gaps, "; ")
}

// EvaluateConfigurationDrift reports whether snapshot (the endpoint's
// actually-active configuration) matches managed (the centrally-managed
// policy that should be in force), independent of whether either one is
// secure -- av.txt names "policy drift" and "conflicting local, domain, MDM
// and centrally managed policies" as a distinct weakness from an outright
// policy gap.
func EvaluateConfigurationDrift(snapshot, managed ConfigurationSnapshot) (ConfigurationState, string) {
	if !snapshot.Coverage.Present() || !managed.Coverage.Present() {
		return ConfigurationUnknown, "drift could not be established: the active or managed configuration state is unavailable"
	}
	if snapshot.RealTimeProtectionEnabled != managed.RealTimeProtectionEnabled ||
		snapshot.CloudProtectionEnabled != managed.CloudProtectionEnabled ||
		snapshot.TamperProtectionEnabled != managed.TamperProtectionEnabled {
		return ConfigurationDrift, "the endpoint's active configuration does not match the centrally managed policy"
	}
	return ConfigurationCompliant, "the endpoint's active configuration matches the centrally managed policy"
}
