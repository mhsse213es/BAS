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

func TestTemplateByID_CredentialPhishingURLChain_ResolvesWithFourOrderedStages(t *testing.T) {
	tmpl, ok := TemplateByID(CredentialPhishingURLChainCampaignID)
	if !ok {
		t.Fatal("want CredentialPhishingURLChainCampaignID to resolve")
	}
	wantKeys := []string{"initial-lure", "click-time-bypass-probe", "detection-check", "response-check"}
	if len(tmpl.Stages) != len(wantKeys) {
		t.Fatalf("len(Stages) = %d, want %d", len(tmpl.Stages), len(wantKeys))
	}
	for i, want := range wantKeys {
		if tmpl.Stages[i].Key != want {
			t.Errorf("Stages[%d].Key = %q, want %q (ordinal order must match the narrative)", i, tmpl.Stages[i].Key, want)
		}
	}
}

func TestCredentialPhishingURLChainTemplate_FirstStageHasNoGate(t *testing.T) {
	tmpl := CredentialPhishingURLChainTemplate()
	first, ok := tmpl.StageByKey("initial-lure")
	if !ok {
		t.Fatal("initial-lure not found")
	}
	if first.Gate != nil {
		t.Error("want the first stage to have no gate -- there is no upstream stage to gate on")
	}
}

func TestCredentialPhishingURLChainTemplate_SecondStageGatesOnUpstreamPreventionFailure(t *testing.T) {
	tmpl := CredentialPhishingURLChainTemplate()
	second, ok := tmpl.StageByKey("click-time-bypass-probe")
	if !ok {
		t.Fatal("click-time-bypass-probe not found")
	}
	if second.Gate == nil {
		t.Fatal("want a gate on the second injected stage")
	}
	if second.Gate.UpstreamStageKey != "initial-lure" {
		t.Errorf("Gate.UpstreamStageKey = %q, want %q", second.Gate.UpstreamStageKey, "initial-lure")
	}
	if second.Gate.UpstreamDimension != DimensionPrevention {
		t.Errorf("Gate.UpstreamDimension = %q, want %q", second.Gate.UpstreamDimension, DimensionPrevention)
	}
	if len(second.Gate.PermittedVerdicts) != 1 || second.Gate.PermittedVerdicts[0] != confirmedFailure {
		t.Errorf("Gate.PermittedVerdicts = %v, want exactly [%q]", second.Gate.PermittedVerdicts, confirmedFailure)
	}
}

func TestCredentialPhishingURLChainTemplate_DerivedStagesHaveNoGateAndNoExpectationID(t *testing.T) {
	tmpl := CredentialPhishingURLChainTemplate()
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
		if s.ReadsFromStageKey != "click-time-bypass-probe" {
			t.Errorf("%q.ReadsFromStageKey = %q, want %q", key, s.ReadsFromStageKey, "click-time-bypass-probe")
		}
	}
}

func TestTemplateByID_MalwarePostDeliveryResponse_ResolvesWithFourOrderedStages(t *testing.T) {
	tmpl, ok := TemplateByID(MalwarePostDeliveryResponseCampaignID)
	if !ok {
		t.Fatal("want MalwarePostDeliveryResponseCampaignID to resolve")
	}
	wantKeys := []string{"malware-delivery", "post-delivery-remediation", "detection-check", "response-check"}
	if len(tmpl.Stages) != len(wantKeys) {
		t.Fatalf("len(Stages) = %d, want %d", len(tmpl.Stages), len(wantKeys))
	}
	for i, want := range wantKeys {
		if tmpl.Stages[i].Key != want {
			t.Errorf("Stages[%d].Key = %q, want %q (ordinal order must match the narrative)", i, tmpl.Stages[i].Key, want)
		}
	}
}

func TestMalwarePostDeliveryResponseTemplate_FirstStageHasNoGate(t *testing.T) {
	tmpl := MalwarePostDeliveryResponseTemplate()
	first, ok := tmpl.StageByKey("malware-delivery")
	if !ok {
		t.Fatal("malware-delivery not found")
	}
	if first.Gate != nil {
		t.Error("want the first stage to have no gate -- there is no upstream stage to gate on")
	}
}

func TestMalwarePostDeliveryResponseTemplate_SecondStageGatesOnUpstreamPreventionFailure(t *testing.T) {
	tmpl := MalwarePostDeliveryResponseTemplate()
	second, ok := tmpl.StageByKey("post-delivery-remediation")
	if !ok {
		t.Fatal("post-delivery-remediation not found")
	}
	if second.Gate == nil {
		t.Fatal("want a gate on the second injected stage")
	}
	if second.Gate.UpstreamStageKey != "malware-delivery" {
		t.Errorf("Gate.UpstreamStageKey = %q, want %q", second.Gate.UpstreamStageKey, "malware-delivery")
	}
	if second.Gate.UpstreamDimension != DimensionPrevention {
		t.Errorf("Gate.UpstreamDimension = %q, want %q", second.Gate.UpstreamDimension, DimensionPrevention)
	}
	if len(second.Gate.PermittedVerdicts) != 1 || second.Gate.PermittedVerdicts[0] != confirmedFailure {
		t.Errorf("Gate.PermittedVerdicts = %v, want exactly [%q]", second.Gate.PermittedVerdicts, confirmedFailure)
	}
}

func TestMalwarePostDeliveryResponseTemplate_DerivedStagesHaveNoGateAndNoExpectationID(t *testing.T) {
	tmpl := MalwarePostDeliveryResponseTemplate()
	for _, key := range []string{"detection-check", "response-check"} {
		s, ok := tmpl.StageByKey(key)
		if !ok {
			t.Fatalf("%q not found", key)
		}
		if s.Kind != StageKindDerived {
			t.Errorf("%q.Kind = %q, want %q", key, s.Kind, StageKindDerived)
		}
		if s.Gate != nil {
			t.Errorf("%q has a gate, want none", key)
		}
		if s.ExpectationID != "" {
			t.Errorf("%q.ExpectationID = %q, want empty", key, s.ExpectationID)
		}
		if s.ReadsFromStageKey != "post-delivery-remediation" {
			t.Errorf("%q.ReadsFromStageKey = %q, want %q", key, s.ReadsFromStageKey, "post-delivery-remediation")
		}
	}
}

func TestTemplateByID_Exfiltration_ResolvesWithFourOrderedStages(t *testing.T) {
	tmpl, ok := TemplateByID(ExfiltrationCampaignID)
	if !ok {
		t.Fatal("want ExfiltrationCampaignID to resolve")
	}
	wantKeys := []string{"credential-lure", "outbound-exfiltration", "detection-check", "response-check"}
	if len(tmpl.Stages) != len(wantKeys) {
		t.Fatalf("len(Stages) = %d, want %d", len(tmpl.Stages), len(wantKeys))
	}
	for i, want := range wantKeys {
		if tmpl.Stages[i].Key != want {
			t.Errorf("Stages[%d].Key = %q, want %q (ordinal order must match the narrative)", i, tmpl.Stages[i].Key, want)
		}
	}
}

func TestExfiltrationTemplate_FirstStageHasNoGate(t *testing.T) {
	tmpl := ExfiltrationTemplate()
	first, ok := tmpl.StageByKey("credential-lure")
	if !ok {
		t.Fatal("credential-lure not found")
	}
	if first.Gate != nil {
		t.Error("want the first stage to have no gate -- there is no upstream stage to gate on")
	}
}

func TestExfiltrationTemplate_SecondStageGatesOnUpstreamPreventionFailure(t *testing.T) {
	tmpl := ExfiltrationTemplate()
	second, ok := tmpl.StageByKey("outbound-exfiltration")
	if !ok {
		t.Fatal("outbound-exfiltration not found")
	}
	if second.Gate == nil {
		t.Fatal("want a gate on the second injected stage")
	}
	if second.Gate.UpstreamStageKey != "credential-lure" {
		t.Errorf("Gate.UpstreamStageKey = %q, want %q", second.Gate.UpstreamStageKey, "credential-lure")
	}
	if second.Gate.UpstreamDimension != DimensionPrevention {
		t.Errorf("Gate.UpstreamDimension = %q, want %q", second.Gate.UpstreamDimension, DimensionPrevention)
	}
	if len(second.Gate.PermittedVerdicts) != 1 || second.Gate.PermittedVerdicts[0] != confirmedFailure {
		t.Errorf("Gate.PermittedVerdicts = %v, want exactly [%q]", second.Gate.PermittedVerdicts, confirmedFailure)
	}
}

func TestExfiltrationTemplate_SecondStageUsesOutboundExpectation(t *testing.T) {
	tmpl := ExfiltrationTemplate()
	second, ok := tmpl.StageByKey("outbound-exfiltration")
	if !ok {
		t.Fatal("outbound-exfiltration not found")
	}
	if second.ExpectationID != "EG-006.known-bad" {
		t.Errorf("ExpectationID = %q, want %q (the sensitive=true/ExpectedQuarantine direction)", second.ExpectationID, "EG-006.known-bad")
	}
}

func TestExfiltrationTemplate_DerivedStagesHaveNoGateAndNoExpectationID(t *testing.T) {
	tmpl := ExfiltrationTemplate()
	for _, key := range []string{"detection-check", "response-check"} {
		s, ok := tmpl.StageByKey(key)
		if !ok {
			t.Fatalf("%q not found", key)
		}
		if s.Kind != StageKindDerived {
			t.Errorf("%q.Kind = %q, want %q", key, s.Kind, StageKindDerived)
		}
		if s.Gate != nil {
			t.Errorf("%q has a gate, want none", key)
		}
		if s.ExpectationID != "" {
			t.Errorf("%q.ExpectationID = %q, want empty", key, s.ExpectationID)
		}
		if s.ReadsFromStageKey != "outbound-exfiltration" {
			t.Errorf("%q.ReadsFromStageKey = %q, want %q", key, s.ReadsFromStageKey, "outbound-exfiltration")
		}
	}
}

func TestTemplateByID_TrustConfigWeakness_ResolvesWithFourOrderedStages(t *testing.T) {
	tmpl, ok := TemplateByID(TrustConfigWeaknessCampaignID)
	if !ok {
		t.Fatal("want TrustConfigWeaknessCampaignID to resolve")
	}
	wantKeys := []string{"direct-path-probe", "relay-path-probe", "detection-check", "response-check"}
	if len(tmpl.Stages) != len(wantKeys) {
		t.Fatalf("len(Stages) = %d, want %d", len(tmpl.Stages), len(wantKeys))
	}
	for i, want := range wantKeys {
		if tmpl.Stages[i].Key != want {
			t.Errorf("Stages[%d].Key = %q, want %q (ordinal order must match the narrative)", i, tmpl.Stages[i].Key, want)
		}
	}
}

func TestTrustConfigWeaknessTemplate_FirstStageHasNoGate(t *testing.T) {
	tmpl := TrustConfigWeaknessTemplate()
	first, ok := tmpl.StageByKey("direct-path-probe")
	if !ok {
		t.Fatal("direct-path-probe not found")
	}
	if first.Gate != nil {
		t.Error("want the first stage to have no gate -- there is no upstream stage to gate on")
	}
}

func TestTrustConfigWeaknessTemplate_SecondStageGatesOnUpstreamPreventionFailure(t *testing.T) {
	tmpl := TrustConfigWeaknessTemplate()
	second, ok := tmpl.StageByKey("relay-path-probe")
	if !ok {
		t.Fatal("relay-path-probe not found")
	}
	if second.Gate == nil {
		t.Fatal("want a gate on the second injected stage")
	}
	if second.Gate.UpstreamStageKey != "direct-path-probe" {
		t.Errorf("Gate.UpstreamStageKey = %q, want %q", second.Gate.UpstreamStageKey, "direct-path-probe")
	}
	if second.Gate.UpstreamDimension != DimensionPrevention {
		t.Errorf("Gate.UpstreamDimension = %q, want %q", second.Gate.UpstreamDimension, DimensionPrevention)
	}
	if len(second.Gate.PermittedVerdicts) != 1 || second.Gate.PermittedVerdicts[0] != confirmedFailure {
		t.Errorf("Gate.PermittedVerdicts = %v, want exactly [%q]", second.Gate.PermittedVerdicts, confirmedFailure)
	}
}

func TestTrustConfigWeaknessTemplate_DerivedStagesHaveNoGateAndNoExpectationID(t *testing.T) {
	tmpl := TrustConfigWeaknessTemplate()
	for _, key := range []string{"detection-check", "response-check"} {
		s, ok := tmpl.StageByKey(key)
		if !ok {
			t.Fatalf("%q not found", key)
		}
		if s.Kind != StageKindDerived {
			t.Errorf("%q.Kind = %q, want %q", key, s.Kind, StageKindDerived)
		}
		if s.Gate != nil {
			t.Errorf("%q has a gate, want none", key)
		}
		if s.ExpectationID != "" {
			t.Errorf("%q.ExpectationID = %q, want empty", key, s.ExpectationID)
		}
		if s.ReadsFromStageKey != "relay-path-probe" {
			t.Errorf("%q.ReadsFromStageKey = %q, want %q", key, s.ReadsFromStageKey, "relay-path-probe")
		}
	}
}

func TestTemplateByID_MailboxCompromise_ResolvesWithFourOrderedStages(t *testing.T) {
	tmpl, ok := TemplateByID(MailboxCompromiseCampaignID)
	if !ok {
		t.Fatal("want MailboxCompromiseCampaignID to resolve")
	}
	wantKeys := []string{"reply-chain-hijack", "weaponized-follow-up", "detection-check", "response-check"}
	if len(tmpl.Stages) != len(wantKeys) {
		t.Fatalf("len(Stages) = %d, want %d", len(tmpl.Stages), len(wantKeys))
	}
	for i, want := range wantKeys {
		if tmpl.Stages[i].Key != want {
			t.Errorf("Stages[%d].Key = %q, want %q (ordinal order must match the narrative)", i, tmpl.Stages[i].Key, want)
		}
	}
}

func TestMailboxCompromiseTemplate_FirstStageHasNoGate(t *testing.T) {
	tmpl := MailboxCompromiseTemplate()
	first, ok := tmpl.StageByKey("reply-chain-hijack")
	if !ok {
		t.Fatal("reply-chain-hijack not found")
	}
	if first.Gate != nil {
		t.Error("want the first stage to have no gate -- there is no upstream stage to gate on")
	}
}

func TestMailboxCompromiseTemplate_SecondStageGatesOnUpstreamPreventionFailure(t *testing.T) {
	tmpl := MailboxCompromiseTemplate()
	second, ok := tmpl.StageByKey("weaponized-follow-up")
	if !ok {
		t.Fatal("weaponized-follow-up not found")
	}
	if second.Gate == nil {
		t.Fatal("want a gate on the second injected stage")
	}
	if second.Gate.UpstreamStageKey != "reply-chain-hijack" {
		t.Errorf("Gate.UpstreamStageKey = %q, want %q", second.Gate.UpstreamStageKey, "reply-chain-hijack")
	}
	if second.Gate.UpstreamDimension != DimensionPrevention {
		t.Errorf("Gate.UpstreamDimension = %q, want %q", second.Gate.UpstreamDimension, DimensionPrevention)
	}
	if len(second.Gate.PermittedVerdicts) != 1 || second.Gate.PermittedVerdicts[0] != confirmedFailure {
		t.Errorf("Gate.PermittedVerdicts = %v, want exactly [%q]", second.Gate.PermittedVerdicts, confirmedFailure)
	}
}

func TestMailboxCompromiseTemplate_DerivedStagesHaveNoGateAndNoExpectationID(t *testing.T) {
	tmpl := MailboxCompromiseTemplate()
	for _, key := range []string{"detection-check", "response-check"} {
		s, ok := tmpl.StageByKey(key)
		if !ok {
			t.Fatalf("%q not found", key)
		}
		if s.Kind != StageKindDerived {
			t.Errorf("%q.Kind = %q, want %q", key, s.Kind, StageKindDerived)
		}
		if s.Gate != nil {
			t.Errorf("%q has a gate, want none", key)
		}
		if s.ExpectationID != "" {
			t.Errorf("%q.ExpectationID = %q, want empty", key, s.ExpectationID)
		}
		if s.ReadsFromStageKey != "weaponized-follow-up" {
			t.Errorf("%q.ReadsFromStageKey = %q, want %q", key, s.ReadsFromStageKey, "weaponized-follow-up")
		}
	}
}

func TestAllTemplates_NoDuplicateCampaignIDs(t *testing.T) {
	ids := []string{
		BECSupplierFraudCampaignID,
		CredentialPhishingURLChainCampaignID,
		MalwarePostDeliveryResponseCampaignID,
		ExfiltrationCampaignID,
		TrustConfigWeaknessCampaignID,
		MailboxCompromiseCampaignID,
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Errorf("duplicate campaign template ID: %q", id)
		}
		seen[id] = true
	}
}
