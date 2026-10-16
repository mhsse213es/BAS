package emailgwefficacy

import "testing"

// TestExpectationByID_CoversEveryRegistryIDExceptEG007 proves
// ExpectationByID resolves every ID EmailGWScenarioRegistry declares,
// except EG-007's own deliberate, documented absence -- a silently
// unresolvable ID for any other scenario would be a real dispatch gap,
// not a modeling choice.
func TestExpectationByID_CoversEveryRegistryIDExceptEG007(t *testing.T) {
	for _, entry := range EmailGWScenarioRegistry() {
		for _, id := range entry.ExpectationIDs {
			_, ok := ExpectationByID(id)
			if entry.ScenarioID == "EG-007" {
				if ok {
					t.Errorf("ExpectationByID(%q): ok = true, want false -- EG-007 is not a MailExpectation scenario", id)
				}
				continue
			}
			if !ok {
				t.Errorf("ExpectationByID(%q): ok = false, want true -- every registry ID except EG-007's must resolve", id)
			}
		}
	}
}

// TestExpectationByID_UnknownID_ReturnsFalse guards the zero-value
// fallback a map lookup gives for free -- an unrecognized ID must
// never resolve to some other scenario's MailExpectation by accident.
func TestExpectationByID_UnknownID_ReturnsFalse(t *testing.T) {
	if _, ok := ExpectationByID("EG-999.no-such-scenario"); ok {
		t.Error("ExpectationByID(unknown id): ok = true, want false")
	}
}

// TestExpectationByID_EG008AndEG010_BothIDsAreTheSameRealSend documents,
// as a checked fact, that EG-008's and EG-010's four IDs collapse to one
// underlying message: PostDeliveryThreatResponseExpectation takes no
// bool, so dispatching any one of them performs an identical injection.
func TestExpectationByID_EG008AndEG010_BothIDsAreTheSameRealSend(t *testing.T) {
	ids := []string{"EG-008.known-good", "EG-008.known-bad", "EG-010.detection", "EG-010.response"}
	want := PostDeliveryThreatResponseExpectation()
	for _, id := range ids {
		exp, ok := ExpectationByID(id)
		if !ok {
			t.Fatalf("ExpectationByID(%q): ok = false, want true", id)
		}
		if exp != want {
			t.Errorf("ExpectationByID(%q) = %+v, want %+v", id, exp, want)
		}
	}
}
