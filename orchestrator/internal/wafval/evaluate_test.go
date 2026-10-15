package wafval

import "testing"

func TestEvaluateClaim_PreventionBlocked_CompleteHigh(t *testing.T) {
	r := EvaluateClaim(
		Expectation{Claim: ClaimPrevention, PolicyBasis: "CRS 942100 SQLi"},
		[]CollectionResult{
			collResult(MechanismWAFEngine, CoverageFound, wafEngineObs(EnforcementBlocked, DetectionMatched)),
			collResult(MechanismOriginApp, CoverageSearchedVerifiedNone, originObs(OriginNotObserved)),
		},
		testKey(),
	)
	if r.Verdict != VerdictBlocked {
		t.Errorf("verdict = %q, want blocked", r.Verdict)
	}
	if r.Completeness != CompletenessComplete {
		t.Errorf("completeness = %q, want complete", r.Completeness)
	}
	if r.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %q, want high", r.Confidence)
	}
	if err := Valid(r.Expectation.Claim, r.Verdict, r.Completeness); err != nil {
		t.Errorf("result violates Valid: %v", err)
	}
}

func TestEvaluateClaim_FalsePositiveAllowed(t *testing.T) {
	r := EvaluateClaim(
		Expectation{Claim: ClaimFalsePositive, PolicyBasis: "legit login"},
		[]CollectionResult{collResult(MechanismWAFEngine, CoverageFound, wafEngineObs(EnforcementAllowed, DetectionNotMatched))},
		testKey(),
	)
	if r.Verdict != VerdictAllowed {
		t.Errorf("verdict = %q, want allowed", r.Verdict)
	}
}

func TestEvaluateClaim_PreventionAllowed_NeverVerdictAllowed(t *testing.T) {
	// Same enforcement=allowed, but a Prevention claim must NEVER return Allowed.
	matched := EvaluateClaim(
		Expectation{Claim: ClaimPrevention},
		[]CollectionResult{
			collResult(MechanismWAFEngine, CoverageFound, wafEngineObs(EnforcementAllowed, DetectionMatched)),
			collResult(MechanismOriginApp, CoverageFound, originObs(OriginReceived)),
		},
		testKey(),
	)
	if matched.Verdict == VerdictAllowed {
		t.Fatal("Prevention claim returned VerdictAllowed — forbidden")
	}
	if matched.Verdict != VerdictDetectedButAllowed {
		t.Errorf("verdict = %q, want detected_but_allowed", matched.Verdict)
	}
	missed := EvaluateClaim(
		Expectation{Claim: ClaimPrevention},
		[]CollectionResult{
			collResult(MechanismWAFEngine, CoverageSearchedVerifiedNone, wafEngineObs(EnforcementAllowed, DetectionNotMatched)),
			collResult(MechanismOriginApp, CoverageFound, originObs(OriginReceived)),
		},
		testKey(),
	)
	if missed.Verdict != VerdictMissed {
		t.Errorf("verdict = %q, want missed", missed.Verdict)
	}
}

func TestEvaluateClaim_WAFOnly_CapsAtMedium(t *testing.T) {
	// Origin telemetry unavailable: still reaches Blocked, but never High.
	r := EvaluateClaim(
		Expectation{Claim: ClaimPrevention},
		[]CollectionResult{
			collResult(MechanismWAFEngine, CoverageFound, wafEngineObs(EnforcementBlocked, DetectionMatched)),
			collResult(MechanismOriginApp, CoverageSourceUnavailable),
		},
		testKey(),
	)
	if r.Verdict != VerdictBlocked {
		t.Errorf("verdict = %q, want blocked", r.Verdict)
	}
	if r.Completeness != CompletenessPartial {
		t.Errorf("completeness = %q, want partial", r.Completeness)
	}
	if r.Confidence == ConfidenceHigh {
		t.Error("confidence reached High on WAF-only evidence — must be capped")
	}
}

func TestEvaluateClaim_ContradictionForcesInconclusive(t *testing.T) {
	sensorAllowed := Observation{
		Mechanism: MechanismIndependentSensor, Provider: "lab-pcap", EventID: "pcap-1",
		RequestID: "req-1", Enforcement: EnforcementAllowed, Detection: DetectionUnknown, Origin: OriginUnknown,
		EvidenceKind: EvidenceObserved,
	}
	r := EvaluateClaim(
		Expectation{Claim: ClaimPrevention},
		[]CollectionResult{
			collResult(MechanismWAFEngine, CoverageFound, wafEngineObs(EnforcementBlocked, DetectionMatched)),
			collResult(MechanismIndependentSensor, CoverageFound, sensorAllowed),
		},
		testKey(),
	)
	if r.Verdict != VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive (contradiction)", r.Verdict)
	}
	if r.Confidence != ConfidenceNone {
		t.Errorf("confidence = %q, want none despite complete collection", r.Confidence)
	}
}

func TestEvaluateClaim_NoObservations_Inconclusive(t *testing.T) {
	r := EvaluateClaim(Expectation{Claim: ClaimPrevention}, nil, testKey())
	if r.Verdict != VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive", r.Verdict)
	}
	if r.Completeness != CompletenessInsufficient {
		t.Errorf("completeness = %q, want insufficient", r.Completeness)
	}
}

func TestEvaluateClaim_IncompleteCoverage_CannotEstablishMissed(t *testing.T) {
	// WAF allowed, but detection search was incomplete: cannot assert not_matched,
	// so cannot be Missed. Detection is Unknown -> Inconclusive.
	r := EvaluateClaim(
		Expectation{Claim: ClaimPrevention},
		[]CollectionResult{
			collResult(MechanismWAFEngine, CoverageSearchIncomplete, wafEngineObs(EnforcementAllowed, DetectionUnknown)),
			collResult(MechanismOriginApp, CoverageFound, originObs(OriginReceived)),
		},
		testKey(),
	)
	if r.Verdict == VerdictMissed {
		t.Fatal("incomplete coverage must never establish Missed")
	}
	if r.Verdict != VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive", r.Verdict)
	}
}
