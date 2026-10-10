package rwevidence

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func TestEndToEnd_VSSInhibition_ThreeCapabilitiesIndependentlyVerified(t *testing.T) {
	tech := VSSInhibition()
	key := controlval.CorrelationKey{RunID: "r-vss", Target: "ws01", Action: tech.ID}

	// Prevention: Defender blocked the vssadmin delete attempt.
	provider := &controlval.FakeProvider{ProviderName: "microsoft_defender", Obs: map[string]controlval.Observation{
		tech.ID: {Outcome: controlval.OutcomeBlocked, EvidenceKind: controlval.EvidenceObserved, Confidence: controlval.ConfidenceHigh},
	}}
	o, err := provider.Observe(context.Background(), key)
	prevention := PreventionFromValidation(tech, controlval.Evaluate(PreventionExpectationFor(tech), &o, err))
	prevention.Provenance = key

	// Recovery: the targeted shadow copies survived.
	recoveryObs := &FakeRecoveryObserver{Results: map[string]SurvivalResult{"r-vss/" + tech.MitreID: SurvivalConfirmed}}
	survival, rerr := recoveryObs.ObserveSurvival(context.Background(), AttemptKey{RunID: "r-vss", TechniqueID: tech.MitreID})
	if rerr != nil {
		t.Fatal(rerr)
	}
	recovery := RecoveryFromSurvival(tech, survival, "")
	recovery.Provenance = key

	// Detection: the windows_vss_inhibition profile verified.
	detection := DetectionFromProfileResult(tech, true, true, "vss-delete-edr fired")
	detection.Provenance = key

	for _, cr := range []CapabilityResult{prevention, recovery, detection} {
		if cr.TechniqueID != "T1490" {
			t.Fatalf("%s: techniqueID = %q, want T1490", cr.Capability, cr.TechniqueID)
		}
		if cr.Provenance != key {
			t.Fatalf("%s: provenance = %+v, want %+v", cr.Capability, cr.Provenance, key)
		}
	}
	if prevention.Verdict != controlval.VerdictPass || recovery.Verdict != controlval.VerdictPass || detection.Verdict != controlval.VerdictPass {
		t.Fatalf("expected all PASS: prevention=%q recovery=%q detection=%q", prevention.Verdict, recovery.Verdict, detection.Verdict)
	}
}

func TestEndToEnd_GeneralizesToASecondTechnique(t *testing.T) {
	// Proves Prevention/Detection are technique-agnostic, not
	// VSSInhibition-specific: the same PreventionExpectationFor/
	// PreventionFromValidation/DetectionFromProfileResult functions, pointed
	// at DataEncryptedForImpact (T1486), grade a blocked encryption attempt
	// correctly with zero code change. Recovery does not apply to T1486
	// itself (that's T1490's domain) -- recorded explicitly via
	// NotApplicable, never silently omitted.
	tech := DataEncryptedForImpact()
	key := controlval.CorrelationKey{RunID: "r-encrypt", Target: "ws01", Action: tech.ID}

	provider := &controlval.FakeProvider{ProviderName: "microsoft_defender", Obs: map[string]controlval.Observation{
		tech.ID: {Outcome: controlval.OutcomeBlocked, EvidenceKind: controlval.EvidenceObserved, Confidence: controlval.ConfidenceHigh},
	}}
	o, err := provider.Observe(context.Background(), key)
	prevention := PreventionFromValidation(tech, controlval.Evaluate(PreventionExpectationFor(tech), &o, err))
	if prevention.Verdict != controlval.VerdictPass {
		t.Fatalf("prevention verdict = %q, want PASS (Controlled Folder Access blocked the mass-encryption attempt)", prevention.Verdict)
	}

	detection := DetectionFromProfileResult(tech, true, true, "mass-encryption-edr and ransom-note-edr both fired")
	if detection.Verdict != controlval.VerdictPass {
		t.Fatalf("detection verdict = %q, want PASS", detection.Verdict)
	}

	recovery := NotApplicable(CapabilityRecovery, tech, "T1486 is about whether files get encrypted, not whether recovery mechanisms survive -- that is T1490's domain")
	if recovery.Verdict != controlval.VerdictSkipped || recovery.SkipReason != controlval.SkipNotApplicable {
		t.Fatalf("recovery = %+v, want SKIPPED/not_applicable", recovery)
	}
}

func TestVSSInhibition_ContainmentAndDataProtectionAreNotApplicable(t *testing.T) {
	// Move 2 of 3: T1490 is a single-host VSS/backup-catalog deletion -- it
	// has no lateral-reachability or exfiltration dimension, so Containment
	// and DataProtection genuinely do not apply. Recorded explicitly, not
	// silently left unrepresented, so a reader can never mistake "doesn't
	// apply" for "wasn't tested" or "failed."
	tech := VSSInhibition()
	containment := NotApplicable(CapabilityContainment, tech, "T1490 is a single-host VSS/backup-catalog deletion -- it has no lateral-reachability dimension to contain")
	dataProtection := NotApplicable(CapabilityDataProtection, tech, "T1490 destroys recovery mechanisms; it does not access, stage, or exfiltrate data")

	for _, cr := range []CapabilityResult{containment, dataProtection} {
		if cr.Verdict != controlval.VerdictSkipped {
			t.Fatalf("%s: verdict = %q, want SKIPPED", cr.Capability, cr.Verdict)
		}
		if cr.SkipReason != controlval.SkipNotApplicable {
			t.Fatalf("%s: skipReason = %q, want not_applicable", cr.Capability, cr.SkipReason)
		}
		if cr.TechniqueID != "T1490" {
			t.Fatalf("%s: techniqueID = %q, want T1490", cr.Capability, cr.TechniqueID)
		}
	}
	if containment.Capability != CapabilityContainment {
		t.Fatalf("capability = %q, want containment", containment.Capability)
	}
	if dataProtection.Capability != CapabilityDataProtection {
		t.Fatalf("capability = %q, want data_protection", dataProtection.Capability)
	}
}

func TestIndependence_PreventionAndRecoveryNeverCrossContaminate(t *testing.T) {
	tech := VSSInhibition()
	key := controlval.CorrelationKey{RunID: "r-mixed", Target: "ws01", Action: tech.ID}

	// Prevention FAILS: Defender allowed the destructive attempt through.
	provider := &controlval.FakeProvider{ProviderName: "microsoft_defender", Obs: map[string]controlval.Observation{
		tech.ID: {Outcome: controlval.OutcomeAllowed, EvidenceKind: controlval.EvidenceObserved, Confidence: controlval.ConfidenceHigh},
	}}
	o, err := provider.Observe(context.Background(), key)
	prevention := PreventionFromValidation(tech, controlval.Evaluate(PreventionExpectationFor(tech), &o, err))

	// Recovery PASSES independently: despite the attempt getting through,
	// the targeted shadow copies still survived (e.g. a backup-side
	// protection caught what the endpoint missed).
	recovery := RecoveryFromSurvival(tech, SurvivalConfirmed, "")

	if prevention.Verdict != controlval.VerdictFail {
		t.Fatalf("prevention verdict = %q, want FAIL", prevention.Verdict)
	}
	if recovery.Verdict != controlval.VerdictPass {
		t.Fatalf("recovery verdict = %q, want PASS -- a Prevention FAIL must never be allowed to drag Recovery down", recovery.Verdict)
	}
}
