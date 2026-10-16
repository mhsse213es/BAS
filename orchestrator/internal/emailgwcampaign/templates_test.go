package emailgwcampaign

import "testing"

func TestTemplateByID_BECSupplierFraud_ResolvesWithFourOrderedStages(t *testing.T) {
	tmpl, ok := TemplateByID(BECSupplierFraudCampaignID)
	if !ok {
		t.Fatal("want BECSupplierFraudCampaignID to resolve")
	}
	wantKeys := []string{"identity-probe", "fraud-payload", "detection-check", "response-check"}
	if len(tmpl.Stages) != len(wantKeys) {
		t.Fatalf("len(Stages) = %d, want %d", len(tmpl.Stages), len(wantKeys))
	}
	for i, want := range wantKeys {
		if tmpl.Stages[i].Key != want {
			t.Errorf("Stages[%d].Key = %q, want %q (ordinal order must match the narrative)", i, tmpl.Stages[i].Key, want)
		}
	}
}

func TestTemplateByID_UnknownID_ReturnsFalse(t *testing.T) {
	if _, ok := TemplateByID("no-such-template"); ok {
		t.Error("want ok=false for an unknown template id")
	}
}

func TestBECSupplierFraudTemplate_FirstStageHasNoGate(t *testing.T) {
	tmpl := BECSupplierFraudTemplate()
	first, ok := tmpl.StageByKey("identity-probe")
	if !ok {
		t.Fatal("identity-probe not found")
	}
	if first.Gate != nil {
		t.Error("want the first stage to have no gate -- there is no upstream stage to gate on")
	}
}

func TestBECSupplierFraudTemplate_DerivedStagesHaveNoGateAndNoExpectationID(t *testing.T) {
	tmpl := BECSupplierFraudTemplate()
	for _, key := range []string{"detection-check", "response-check"} {
		s, ok := tmpl.StageByKey(key)
		if !ok {
			t.Fatalf("%q not found", key)
		}
		if s.Kind != StageKindDerived {
			t.Errorf("%q.Kind = %q, want %q", key, s.Kind, StageKindDerived)
		}
		if s.Gate != nil {
			t.Errorf("%q has a gate, want none -- a derived stage's fate cascades from the stage it reads, not a separately-evaluated gate", key)
		}
		if s.ExpectationID != "" {
			t.Errorf("%q.ExpectationID = %q, want empty -- a derived stage never dispatches its own injection", key, s.ExpectationID)
		}
		if s.ReadsFromStageKey != "fraud-payload" {
			t.Errorf("%q.ReadsFromStageKey = %q, want %q", key, s.ReadsFromStageKey, "fraud-payload")
		}
	}
}

func TestStageByKey_UnknownKey_ReturnsFalse(t *testing.T) {
	tmpl := BECSupplierFraudTemplate()
	if _, ok := tmpl.StageByKey("no-such-stage"); ok {
		t.Error("want ok=false for an unknown stage key")
	}
}
