package networkefficacy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
)

func TestControlExpectation_SerializesWithCamelCaseKeys(t *testing.T) {
	exp := ControlExpectation{FlowSourceCIDR: "10.0.1.0/24", FlowDestCIDR: "10.0.2.0/24", FlowPort: 443, ExpectedAction: ExpectedBlock, ControlProduct: "opnsense"}
	data, err := json.Marshal(exp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := string(data)
	for _, want := range []string{`"flowSourceCidr"`, `"flowDestCidr"`, `"flowPort"`, `"expectedAction"`, `"controlProduct"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("got %s, want it to contain %s", raw, want)
		}
	}
	if strings.Contains(raw, `"FlowSourceCIDR"`) || strings.Contains(raw, `"ExpectedAction"`) {
		t.Fatalf("got %s, want no PascalCase keys", raw)
	}
}

func TestFirewallEvidence_SerializesWithCamelCaseKeys(t *testing.T) {
	ev := FirewallEvidence{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Action: "block", Source: SourceSynthetic}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := string(data)
	for _, want := range []string{`"sourceIp"`, `"destIp"`, `"port"`, `"action"`, `"source"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("got %s, want it to contain %s", raw, want)
		}
	}
	if strings.Contains(raw, `"SourceIP"`) || strings.Contains(raw, `"Action"`) {
		t.Fatalf("got %s, want no PascalCase keys", raw)
	}
}

func TestIDSEvidence_SerializesWithCamelCaseKeys(t *testing.T) {
	ev := IDSEvidence{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, AlertName: "ET SCAN", Source: SourceFixture}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := string(data)
	for _, want := range []string{`"sourceIp"`, `"destIp"`, `"alertName"`, `"source"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("got %s, want it to contain %s", raw, want)
		}
	}
	if strings.Contains(raw, `"AlertName"`) {
		t.Fatalf("got %s, want no PascalCase keys", raw)
	}
}

func TestEfficacyResult_SerializesWithCamelCaseKeysAndOmitsEmptyOptionals(t *testing.T) {
	result := EfficacyResult{
		Expectation: ControlExpectation{FlowSourceCIDR: "10.0.1.0/24", FlowDestCIDR: "10.0.2.0/24", FlowPort: 443, ExpectedAction: ExpectedBlock},
		Observation: networkgraph.NetworkObservation{Target: networkgraph.Target{Host: "10.0.2.5", Port: 443}, State: cloudgraph.Unknown},
		Verdict:     VerdictInconclusive,
		Reason:      "no firewall log entry found",
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := string(data)
	for _, want := range []string{`"expectation"`, `"observation"`, `"verdict"`, `"reason"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("got %s, want it to contain %s", raw, want)
		}
	}
	for _, unwanted := range []string{`"firewallEvidence"`, `"idsEvidence"`, `"contradiction"`, `"policyEvaluation"`} {
		if strings.Contains(raw, unwanted) {
			t.Fatalf("got %s, want %s omitted when empty", raw, unwanted)
		}
	}
}
