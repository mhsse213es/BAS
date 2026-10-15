package webgwefficacy

import (
	"testing"
	"time"
)

// TestMapObligationToScenarioEvidence_IndiaCERTIn_NetworkSecurityControls
// maps domain 11 end-to-end: obligation -> control -> scenario ->
// evidence, for India's real CERT-In Directions on Information
// Security Practices (MeitY No.20(3)/2022-CERT-In, control CI-13,
// "Network security controls -- firewall, IDS/IPS, network
// segmentation", also seeded in
// internal/compliance/mappings/cert_in.yaml). The scenario is a real
// execution of Phase 3's fail-closed check -- a firewall-class
// control that fails open during an outage is exactly the gap CI-13
// exists to catch.
func TestMapObligationToScenarioEvidence_IndiaCERTIn_NetworkSecurityControls(t *testing.T) {
	obligation := RegulatoryObligation{
		ID:              "cert-in-ci-13",
		Jurisdiction:    "India",
		Regulator:       "CERT-In / MeitY",
		Title:           "Network security controls -- firewall, IDS/IPS, network segmentation",
		SourceReference: "CERT-In Directions on Information Security Practices, MeitY No.20(3)/2022-CERT-In",
		Version:         "2022",
		EffectiveDate:   time.Date(2022, 4, 28, 0, 0, 0, 0, time.UTC),
		ControlLabel:    "webgwefficacy.failuremode",
	}

	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	exp := FailureModeExpectation{ScenarioLabel: "gateway-outage-datacenter-failover", ExpectedBehavior: ExpectedFailClosed}
	provider := NewFixtureFailureModeProvider([]FailureModeEvidence{
		{ScenarioLabel: exp.ScenarioLabel, ObservedBehavior: ExpectedFailClosed, Timestamp: now, Source: SourceFixture},
	})
	verdict := VerifyFailureModeExpectation(exp, provider, window)

	snapshot := MapObligationToScenarioEvidence(obligation, exp.ScenarioLabel, verdict.Verdict, now)

	if snapshot.ObligationID != obligation.ID {
		t.Errorf("ObligationID = %q, want %q", snapshot.ObligationID, obligation.ID)
	}
	if snapshot.Status != ObligationSnapshotCaptured {
		t.Errorf("Status = %q, want %q -- the scenario genuinely passed", snapshot.Status, ObligationSnapshotCaptured)
	}
	if snapshot.CapturedVerdict != VerdictPass {
		t.Errorf("CapturedVerdict = %q, want %q", snapshot.CapturedVerdict, VerdictPass)
	}
}

// TestMapObligationToScenarioEvidence_UAEInformationAssurance_BoundaryProtection
// maps domain 08 end-to-end for the UAE's Information Assurance
// Regulation (TDRA, v1.1, Communications control family --
// independent secondary sources disagree on its exact T-number, T4
// vs T8, so this cites the cross-referenced NIST SP 800-53 control it
// corresponds to, SC-07 Boundary Protection, rather than inventing
// UAE-specific control text this session could not independently
// verify from the primary document). The scenario is a real execution
// of Phase 3's proxy-bypass check -- a DNS-over-HTTPS bypass getting
// caught is a direct instance of monitoring and controlling
// communications at the external boundary.
func TestMapObligationToScenarioEvidence_UAEInformationAssurance_BoundaryProtection(t *testing.T) {
	obligation := RegulatoryObligation{
		ID:              "uae-ia-sc-07",
		Jurisdiction:    "UAE",
		Regulator:       "TDRA (UAE Information Assurance Regulation)",
		Title:           "Boundary protection -- monitor and control communications at external boundaries",
		SourceReference: "UAE Information Assurance Regulation v1.1, Communications control family (cross-referenced to NIST SP 800-53 SC-07)",
		Version:         "1.1",
		ControlLabel:    "webgwefficacy.proxybypass",
		Note:            "Secondary sources disagree on this family's T-number (T4 per one source, T8 per another); SC-07 is cited as the verifiable anchor rather than unverified primary-document control text.",
	}

	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	exp := HTTPExpectation{RequestURL: "https://dns.google/dns-query", ExpectedAction: ExpectedBlock}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "block", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window)

	snapshot := MapObligationToScenarioEvidence(obligation, "doh-bypass-caught", result.Prevention.Verdict, now)

	if snapshot.Status != ObligationSnapshotCaptured {
		t.Errorf("Status = %q, want %q", snapshot.Status, ObligationSnapshotCaptured)
	}
	if snapshot.CapturedVerdict != VerdictPass {
		t.Errorf("CapturedVerdict = %q, want %q", snapshot.CapturedVerdict, VerdictPass)
	}
}

// TestMapObligationToScenarioEvidence_RBICyberSecurityFramework_FirewallPerimeterSecurity
// maps domain 08 end-to-end for India's second regulator, the RBI
// Cyber Security Framework (Circular RBI/2015-16/418, "Cyber Security
// Framework in Banks," dated 2 June 2016 -- independently verified
// this session against rbi.org.in's own notification page -- control
// NET-02, "Firewall and perimeter security -- rules reviewed,
// inbound/outbound filtered," also seeded in
// internal/compliance/mappings/rbi_csf.yaml). Deliberately mapped to
// the proxy-bypass scenario (domain 08), distinct from the existing
// CERT-In obligation's fail-closed mapping (domain 11), so India's
// two regulators are each independently evidenced rather than both
// resting on the same proof.
func TestMapObligationToScenarioEvidence_RBICyberSecurityFramework_FirewallPerimeterSecurity(t *testing.T) {
	obligation := RegulatoryObligation{
		ID:              "rbi-csf-net-02",
		Jurisdiction:    "India",
		Regulator:       "RBI",
		Title:           "Firewall and perimeter security -- rules reviewed, inbound/outbound filtered",
		SourceReference: "RBI Circular RBI/2015-16/418 (DBS.CO/CSITE/BC.11/33.01.001/2015-16), \"Cyber Security Framework in Banks\"",
		Version:         "2016",
		EffectiveDate:   time.Date(2016, 6, 2, 0, 0, 0, 0, time.UTC),
		ControlLabel:    "webgwefficacy.proxybypass",
	}

	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	exp := HTTPExpectation{RequestURL: "https://dns.google/dns-query", ExpectedAction: ExpectedBlock}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "block", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window)

	snapshot := MapObligationToScenarioEvidence(obligation, "doh-bypass-caught", result.Prevention.Verdict, now)

	if snapshot.Status != ObligationSnapshotCaptured {
		t.Errorf("Status = %q, want %q", snapshot.Status, ObligationSnapshotCaptured)
	}
	if snapshot.CapturedVerdict != VerdictPass {
		t.Errorf("CapturedVerdict = %q, want %q", snapshot.CapturedVerdict, VerdictPass)
	}
}

// TestMapObligationToScenarioEvidence_InconclusiveVerdict_StatusIncomplete
// proves missing evidence is captured as Incomplete, never silently
// treated as if the obligation had been proven met.
func TestMapObligationToScenarioEvidence_InconclusiveVerdict_StatusIncomplete(t *testing.T) {
	obligation := RegulatoryObligation{ID: "test-obligation"}
	snapshot := MapObligationToScenarioEvidence(obligation, "some-scenario", VerdictInconclusive, time.Now())

	if snapshot.Status != ObligationSnapshotIncomplete {
		t.Errorf("Status = %q, want %q -- an Inconclusive verdict must never be captured as if proven", snapshot.Status, ObligationSnapshotIncomplete)
	}
}

func TestMapObligationToScenarioEvidence_UnsupportedVerdict_StatusIncomplete(t *testing.T) {
	obligation := RegulatoryObligation{ID: "test-obligation"}
	snapshot := MapObligationToScenarioEvidence(obligation, "some-scenario", VerdictUnsupported, time.Now())

	if snapshot.Status != ObligationSnapshotIncomplete {
		t.Errorf("Status = %q, want %q", snapshot.Status, ObligationSnapshotIncomplete)
	}
}

// TestMapObligationToScenarioEvidence_FailVerdict_StatusCaptured confirms
// a Fail is still a genuinely captured result -- the obligation's
// control was tested and found NOT to hold, which is itself a real,
// capturable finding, not an incomplete one.
func TestMapObligationToScenarioEvidence_FailVerdict_StatusCaptured(t *testing.T) {
	obligation := RegulatoryObligation{ID: "test-obligation"}
	snapshot := MapObligationToScenarioEvidence(obligation, "some-scenario", VerdictFail, time.Now())

	if snapshot.Status != ObligationSnapshotCaptured {
		t.Errorf("Status = %q, want %q -- a Fail is a genuine captured finding, not missing evidence", snapshot.Status, ObligationSnapshotCaptured)
	}
}
