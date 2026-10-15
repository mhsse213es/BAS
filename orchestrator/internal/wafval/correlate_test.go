package wafval

import "testing"

func TestCorrelate_CrossMechanismAgreement(t *testing.T) {
	v := Correlate(testKey(), []CollectionResult{
		collResult(MechanismWAFEngine, CoverageFound, wafEngineObs(EnforcementBlocked, DetectionMatched)),
		collResult(MechanismOriginApp, CoverageSearchedVerifiedNone, originObs(OriginNotObserved)),
	})
	if v.EnforcementAx.State != AxisAgree || v.EnforcementAx.Enforcement != EnforcementBlocked {
		t.Errorf("enforcement = %+v, want Agree/blocked", v.EnforcementAx)
	}
	if v.DetectionAx.State != AxisAgree || v.DetectionAx.Detection != DetectionMatched {
		t.Errorf("detection = %+v, want Agree/matched", v.DetectionAx)
	}
	if len(v.Raw) != 2 {
		t.Errorf("Raw len = %d, want 2 (observations preserved)", len(v.Raw))
	}
}

func TestCorrelate_DuplicateEventID_NotIndependentCorroboration(t *testing.T) {
	// Same WAF event reported twice (same EventID) must count once.
	o := wafEngineObs(EnforcementBlocked, DetectionMatched, withEventID("dup"))
	v := Correlate(testKey(), []CollectionResult{
		collResult(MechanismWAFEngine, CoverageFound, o, o),
	})
	if v.EnforcementAx.State != AxisAgree || v.EnforcementAx.Enforcement != EnforcementBlocked {
		t.Errorf("enforcement = %+v, want Agree/blocked (duplicate collapsed)", v.EnforcementAx)
	}
}

func TestCorrelate_SameMechanismDisagreement_Ambiguous(t *testing.T) {
	// One WAF mechanism emits two DISTINCT events that disagree on enforcement.
	v := Correlate(testKey(), []CollectionResult{
		collResult(MechanismWAFEngine, CoverageFound,
			wafEngineObs(EnforcementBlocked, DetectionMatched, withEventID("e1")),
			wafEngineObs(EnforcementAllowed, DetectionMatched, withEventID("e2")),
		),
	})
	if v.EnforcementAx.State != AxisAmbiguous {
		t.Errorf("enforcement state = %q, want ambiguous", v.EnforcementAx.State)
	}
	if len(v.Raw) != 2 {
		t.Errorf("Raw len = %d, want 2 (both events preserved)", len(v.Raw))
	}
}

func TestCorrelate_CrossMechanismContradiction(t *testing.T) {
	// WAF says blocked; origin reports it received/processed the request.
	v := Correlate(testKey(), []CollectionResult{
		collResult(MechanismWAFEngine, CoverageFound, wafEngineObs(EnforcementBlocked, DetectionMatched)),
		collResult(MechanismOriginApp, CoverageFound, originObs(OriginReceived)),
	})
	if v.OriginAx.State != AxisAgree || v.OriginAx.Origin != OriginReceived {
		t.Errorf("origin = %+v, want Agree/received", v.OriginAx)
	}
	// Only WAF reports enforcement here; origin reports the origin axis.
	if v.EnforcementAx.State != AxisAgree || v.EnforcementAx.Enforcement != EnforcementBlocked {
		t.Errorf("enforcement = %+v, want Agree/blocked (only WAF reports enforcement)", v.EnforcementAx)
	}
}

func TestCorrelate_CrossMechanismContradiction_SameAxis(t *testing.T) {
	wafBlocked := wafEngineObs(EnforcementBlocked, DetectionMatched)
	sensorAllowed := Observation{
		Mechanism: MechanismIndependentSensor, Provider: "lab-pcap", EventID: "pcap-1",
		RequestID: "req-1", Enforcement: EnforcementAllowed, Detection: DetectionUnknown, Origin: OriginUnknown,
		EvidenceKind: EvidenceObserved,
	}
	v := Correlate(testKey(), []CollectionResult{
		collResult(MechanismWAFEngine, CoverageFound, wafBlocked),
		collResult(MechanismIndependentSensor, CoverageFound, sensorAllowed),
	})
	if v.EnforcementAx.State != AxisContradictory {
		t.Errorf("enforcement state = %q, want contradictory", v.EnforcementAx.State)
	}
}
