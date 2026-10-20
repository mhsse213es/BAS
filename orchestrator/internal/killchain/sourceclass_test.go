package killchain

import "testing"

func TestSourceClass_IdentityAcceptsHostRecordsOnly(t *testing.T) {
	for _, c := range []SourceClass{SourceEventLog, SourceEDRTelemetry} {
		if !SourceClassAllowed("credential-access", c) {
			t.Errorf("identity should accept %s", c)
		}
	}
	// A manual observation or a network sensor cannot prove an identity action happened on the host.
	for _, c := range []SourceClass{SourceNetworkSensor, SourceOperatorObservation} {
		if SourceClassAllowed("credential-access", c) {
			t.Errorf("identity must refuse %s", c)
		}
	}
}

func TestSourceClass_LateralAcceptsEventLogSensorOrEDR(t *testing.T) {
	for _, c := range []SourceClass{SourceEventLog, SourceNetworkSensor, SourceEDRTelemetry} {
		if !SourceClassAllowed("caldera-lateral-movement", c) {
			t.Errorf("lateral should accept %s", c)
		}
	}
	if SourceClassAllowed("caldera-lateral-movement", SourceOperatorObservation) {
		t.Errorf("lateral must refuse an operator observation")
	}
}

func TestSourceClass_UnknownClassNeverAllowed(t *testing.T) {
	if SourceClassAllowed("credential-access", SourceClass("")) {
		t.Errorf("an empty class must never be allowed")
	}
	if SourceClassAllowed("credential-access", SourceClass("trust-me")) {
		t.Errorf("an unrecognised class must never be allowed")
	}
}
