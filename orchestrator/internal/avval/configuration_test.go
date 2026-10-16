package avval

import "testing"

func compliantSnapshot() ConfigurationSnapshot {
	return ConfigurationSnapshot{
		RealTimeProtectionEnabled: true,
		CloudProtectionEnabled:    true,
		TamperProtectionEnabled:   true,
		SignatureAgeHours:         2,
		Coverage:                  CoverageFound,
	}
}

func TestEvaluateConfigurationSnapshot_Compliant(t *testing.T) {
	baseline := ConfigurationBaseline{RequireRealTimeProtection: true, RequireCloudProtection: true, RequireTamperProtection: true, MaxSignatureAgeHours: 24}
	state, _ := EvaluateConfigurationSnapshot(compliantSnapshot(), baseline)
	if state != ConfigurationCompliant {
		t.Errorf("state = %q, want %q", state, ConfigurationCompliant)
	}
}

func TestEvaluateConfigurationSnapshot_RealTimeProtectionDisabled_PolicyGap(t *testing.T) {
	snapshot := compliantSnapshot()
	snapshot.RealTimeProtectionEnabled = false
	baseline := ConfigurationBaseline{RequireRealTimeProtection: true}
	state, reason := EvaluateConfigurationSnapshot(snapshot, baseline)
	if state != ConfigurationPolicyGap {
		t.Errorf("state = %q, want %q", state, ConfigurationPolicyGap)
	}
	if reason == "" {
		t.Error("reason should name the gap")
	}
}

func TestEvaluateConfigurationSnapshot_StaleSignatures_PolicyGap(t *testing.T) {
	snapshot := compliantSnapshot()
	snapshot.SignatureAgeHours = 72
	baseline := ConfigurationBaseline{MaxSignatureAgeHours: 24}
	state, _ := EvaluateConfigurationSnapshot(snapshot, baseline)
	if state != ConfigurationPolicyGap {
		t.Errorf("state = %q, want %q", state, ConfigurationPolicyGap)
	}
}

func TestEvaluateConfigurationSnapshot_DisallowedExclusion_PolicyGap(t *testing.T) {
	snapshot := compliantSnapshot()
	snapshot.Exclusions = []string{`C:\Users\Public\Downloads`}
	baseline := ConfigurationBaseline{DisallowedExclusions: []string{`C:\Users\Public\Downloads`}}
	state, _ := EvaluateConfigurationSnapshot(snapshot, baseline)
	if state != ConfigurationPolicyGap {
		t.Errorf("state = %q, want %q", state, ConfigurationPolicyGap)
	}
}

func TestEvaluateConfigurationSnapshot_Unreadable_Unknown(t *testing.T) {
	snapshot := ConfigurationSnapshot{Coverage: CoverageSourceUnavailable}
	state, _ := EvaluateConfigurationSnapshot(snapshot, ConfigurationBaseline{RequireRealTimeProtection: true})
	if state != ConfigurationUnknown {
		t.Errorf("state = %q, want %q (must fail closed, never infer Compliant)", state, ConfigurationUnknown)
	}
}

func TestEvaluateConfigurationDrift_Matches_Compliant(t *testing.T) {
	state, _ := EvaluateConfigurationDrift(compliantSnapshot(), compliantSnapshot())
	if state != ConfigurationCompliant {
		t.Errorf("state = %q, want %q", state, ConfigurationCompliant)
	}
}

func TestEvaluateConfigurationDrift_LocalOverrideDisablesRealTime_Drift(t *testing.T) {
	active := compliantSnapshot()
	active.RealTimeProtectionEnabled = false // local override
	managed := compliantSnapshot()           // centrally managed policy still requires it on
	state, _ := EvaluateConfigurationDrift(active, managed)
	if state != ConfigurationDrift {
		t.Errorf("state = %q, want %q", state, ConfigurationDrift)
	}
}

func TestEvaluateConfigurationDrift_ManagedUnavailable_Unknown(t *testing.T) {
	managed := ConfigurationSnapshot{Coverage: CoverageSourceUnavailable}
	state, _ := EvaluateConfigurationDrift(compliantSnapshot(), managed)
	if state != ConfigurationUnknown {
		t.Errorf("state = %q, want %q", state, ConfigurationUnknown)
	}
}
