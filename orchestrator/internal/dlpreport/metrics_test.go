package dlpreport

import "testing"

func byChannel(r Record) string { return r.ActionAttempted }

func TestPreventionByGroup_CountsBlockedQuarantinedEncryptedAsPrevented(t *testing.T) {
	recs := []Record{
		{ActionAttempted: "usb", Enforcement: EnforcementBlocked},
		{ActionAttempted: "usb", Enforcement: EnforcementQuarantined},
		{ActionAttempted: "usb", Enforcement: EnforcementEncrypted},
	}
	got := PreventionByGroup(recs, byChannel)["usb"]
	if got.Prevented != 3 || got.Total != 3 {
		t.Fatalf("Prevented=%d Total=%d, want 3/3", got.Prevented, got.Total)
	}
	if got.Rate != 1.0 {
		t.Errorf("Rate = %v, want 1.0", got.Rate)
	}
}

func TestPreventionByGroup_ChallengedIsNotPrevented(t *testing.T) {
	recs := []Record{{ActionAttempted: "web", Enforcement: EnforcementChallenged}}
	got := PreventionByGroup(recs, byChannel)["web"]
	if got.Prevented != 0 {
		t.Errorf("Prevented = %d, want 0: a challenge is not prevention", got.Prevented)
	}
	if got.Challenged != 1 {
		t.Errorf("Challenged = %d, want 1", got.Challenged)
	}
}

func TestPreventionByGroup_UnknownCountsInTotalButNotPrevented(t *testing.T) {
	recs := []Record{
		{ActionAttempted: "mail", Enforcement: EnforcementBlocked},
		{ActionAttempted: "mail", Enforcement: EnforcementUnknown, Limitations: "no observer"},
	}
	got := PreventionByGroup(recs, byChannel)["mail"]
	if got.Total != 2 {
		t.Errorf("Total = %d, want 2: unknown must stay in the denominator", got.Total)
	}
	if got.Unknown != 1 {
		t.Errorf("Unknown = %d, want 1", got.Unknown)
	}
	if got.Rate != 0.5 {
		t.Errorf("Rate = %v, want 0.5", got.Rate)
	}
}

func TestPreventionByGroup_UnrecognizedEnforcementIsUnknownNotPrevented(t *testing.T) {
	recs := []Record{{ActionAttempted: "api", Enforcement: EnforcementOutcome("future-value")}}
	got := PreventionByGroup(recs, byChannel)["api"]
	if got.Prevented != 0 {
		t.Errorf("Prevented = %d, want 0 for an unrecognized value", got.Prevented)
	}
	if got.Unknown != 1 {
		t.Errorf("Unknown = %d, want 1", got.Unknown)
	}
}

func TestPreventionByGroup_AllUnknownGroupHasZeroMeasurableAndZeroRate(t *testing.T) {
	recs := []Record{{ActionAttempted: "cloud", Enforcement: EnforcementUnknown}}
	got := PreventionByGroup(recs, byChannel)["cloud"]
	if got.Measurable != 0 {
		t.Errorf("Measurable = %d, want 0", got.Measurable)
	}
	if got.Rate != 0 {
		t.Errorf("Rate = %v, want 0 for an unmeasurable group", got.Rate)
	}
}

func TestPreventionByGroup_MeasurableCountsNonUnknown(t *testing.T) {
	recs := []Record{
		{ActionAttempted: "usb", Enforcement: EnforcementAllowed},
		{ActionAttempted: "usb", Enforcement: EnforcementOverridden},
		{ActionAttempted: "usb", Enforcement: EnforcementUnknown},
	}
	got := PreventionByGroup(recs, byChannel)["usb"]
	if got.Measurable != 2 {
		t.Errorf("Measurable = %d, want 2", got.Measurable)
	}
	if got.Allowed != 1 || got.Overridden != 1 {
		t.Errorf("Allowed=%d Overridden=%d, want 1/1", got.Allowed, got.Overridden)
	}
}

func TestPreventionByGroup_SeparatesGroupsByKey(t *testing.T) {
	recs := []Record{
		{ActionAttempted: "usb", Enforcement: EnforcementBlocked},
		{ActionAttempted: "web", Enforcement: EnforcementAllowed},
	}
	got := PreventionByGroup(recs, byChannel)
	if len(got) != 2 {
		t.Fatalf("groups = %d, want 2", len(got))
	}
	if got["usb"].Prevented != 1 || got["web"].Prevented != 0 {
		t.Errorf("groups mixed up: %+v", got)
	}
}

func TestPreventionByGroup_EmptyInputReturnsEmptyMap(t *testing.T) {
	got := PreventionByGroup(nil, byChannel)
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}
