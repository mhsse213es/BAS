package wafval

import "time"

type obsOpt func(*Observation)

func withEventID(id string) obsOpt           { return func(o *Observation) { o.EventID = id } }
func withEvidenceKind(k EvidenceKind) obsOpt { return func(o *Observation) { o.EvidenceKind = k } }

func testKey() CorrelationKey {
	return CorrelationKey{
		TestExecutionID: "exec-1",
		RequestID:       "req-1",
		Target:          "https://app.lab/login",
		Window:          TimeWindow{Start: time.Unix(0, 0), End: time.Unix(60, 0)},
	}
}

func wafEngineObs(enf EnforcementAction, det DetectionOutcome, opts ...obsOpt) Observation {
	o := Observation{
		Mechanism:    MechanismWAFEngine,
		Provider:     "lab-modsecurity",
		EventID:      "waf-evt",
		RequestID:    "req-1",
		ObservedAt:   time.Unix(1, 0),
		Enforcement:  enf,
		Detection:    det,
		Origin:       OriginUnknown,
		EvidenceKind: EvidenceObserved,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

func originObs(origin OriginObservation, opts ...obsOpt) Observation {
	o := Observation{
		Mechanism:    MechanismOriginApp,
		Provider:     "lab-origin",
		EventID:      "origin-evt",
		RequestID:    "req-1",
		ObservedAt:   time.Unix(2, 0),
		Enforcement:  EnforcementUnknown,
		Detection:    DetectionUnknown,
		Origin:       origin,
		EvidenceKind: EvidenceObserved,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

func collResult(m Mechanism, cov Coverage, obs ...Observation) CollectionResult {
	return CollectionResult{Mechanism: m, Coverage: cov, Observations: obs}
}
