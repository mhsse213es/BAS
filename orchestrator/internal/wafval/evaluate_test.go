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

func TestEvaluateClaim_BlockedButOriginReceived_Contradiction(t *testing.T) {
	// WAF says it blocked, but the origin reports it received the request: the
	// "block" did not prevent reach. This cross-axis inconsistency must force
	// Inconclusive with no confidence, never a clean Blocked/High (spec §6).
	r := EvaluateClaim(
		Expectation{Claim: ClaimPrevention},
		[]CollectionResult{
			collResult(MechanismWAFEngine, CoverageFound, wafEngineObs(EnforcementBlocked, DetectionMatched)),
			collResult(MechanismOriginApp, CoverageFound, originObs(OriginReceived)),
		},
		testKey(),
	)
	if r.Verdict != VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive (block contradicted by origin received)", r.Verdict)
	}
	if r.Confidence != ConfidenceNone {
		t.Errorf("confidence = %q, want none (cross-axis contradiction)", r.Confidence)
	}
}

func TestEvaluateClaim_UnknownClaim_InconclusiveNoPanic(t *testing.T) {
	// An unrecognized claim type is caller error, not evidence: return
	// Inconclusive, never panic.
	r := EvaluateClaim(
		Expectation{Claim: ClaimType("bogus")},
		[]CollectionResult{collResult(MechanismWAFEngine, CoverageFound, wafEngineObs(EnforcementBlocked, DetectionMatched))},
		testKey(),
	)
	if r.Verdict != VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive for unknown claim", r.Verdict)
	}
	if r.Confidence != ConfidenceNone {
		t.Errorf("confidence = %q, want none for unknown claim", r.Confidence)
	}
}

func TestEvaluateClaim_AmbiguousAxis_ConfidenceCappedLow(t *testing.T) {
	// Same-mechanism distinct events disagree on enforcement -> Ambiguous ->
	// Inconclusive. Even with complete coverage, confidence must not stay High.
	r := EvaluateClaim(
		Expectation{Claim: ClaimPrevention},
		[]CollectionResult{
			collResult(MechanismWAFEngine, CoverageFound,
				wafEngineObs(EnforcementBlocked, DetectionMatched, withEventID("e1")),
				wafEngineObs(EnforcementAllowed, DetectionMatched, withEventID("e2")),
			),
			collResult(MechanismOriginApp, CoverageSearchedVerifiedNone, originObs(OriginNotObserved)),
		},
		testKey(),
	)
	if r.Verdict != VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive (ambiguous enforcement)", r.Verdict)
	}
	if r.Confidence == ConfidenceHigh {
		t.Error("confidence reached High on ambiguous evidence — must be capped")
	}
	if r.Confidence != ConfidenceLow {
		t.Errorf("confidence = %q, want low (ambiguous claim axis)", r.Confidence)
	}
}

func TestResult_NotTestedDistinctFromInconclusive(t *testing.T) {
	// Executed-but-empty attempt -> Inconclusive (a Result exists).
	executed := EvaluateClaim(Expectation{Claim: ClaimPrevention}, []CollectionResult{
		collResult(MechanismWAFEngine, CoverageSourceUnavailable),
	}, testKey())
	if executed.Verdict != VerdictInconclusive {
		t.Errorf("executed-but-empty verdict = %q, want inconclusive", executed.Verdict)
	}
	// The evaluator must never emit a not-tested-like verdict. Every verdict it
	// can return is one of the six terminal Verdict values; none is "not_tested".
	for _, v := range []Verdict{
		VerdictBlocked, VerdictDetectedButAllowed, VerdictMissed,
		VerdictIncorrectlyBlocked, VerdictAllowed, VerdictInconclusive,
	} {
		if string(v) == "not_tested" {
			t.Fatal("not_tested must not be a Verdict value")
		}
	}
}
