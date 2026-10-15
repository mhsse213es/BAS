package webgwefficacy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHTTPExpectation_SerializesWithCamelCaseKeys(t *testing.T) {
	exp := HTTPExpectation{RequestURL: "https://malware.example/payload", URLCategory: "malware", ExpectedAction: ExpectedBlock, ControlProduct: "cloudflare-gateway"}
	data, err := json.Marshal(exp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := string(data)
	for _, want := range []string{`"requestUrl"`, `"urlCategory"`, `"expectedAction"`, `"controlProduct"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("got %s, want it to contain %s", raw, want)
		}
	}
	if strings.Contains(raw, `"RequestURL"`) || strings.Contains(raw, `"ExpectedAction"`) {
		t.Fatalf("got %s, want no PascalCase keys", raw)
	}
}

func TestGatewayEvidence_SerializesWithCamelCaseKeys(t *testing.T) {
	ev := GatewayEvidence{RequestURL: "https://malware.example/payload", Action: "block", Source: SourceSynthetic}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := string(data)
	for _, want := range []string{`"requestUrl"`, `"action"`, `"source"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("got %s, want it to contain %s", raw, want)
		}
	}
	if strings.Contains(raw, `"RequestURL"`) || strings.Contains(raw, `"Action"`) {
		t.Fatalf("got %s, want no PascalCase keys", raw)
	}
}

func TestEfficacyResult_SerializesWithCamelCaseKeysAndOmitsEmptyEvidence(t *testing.T) {
	result := EfficacyResult{
		Expectation: HTTPExpectation{RequestURL: "https://malware.example/payload", ExpectedAction: ExpectedBlock},
		Observation: HTTPObservation{RequestURL: "https://malware.example/payload", ClientResult: "succeeded"},
		Prevention:  VerdictDetail{Verdict: VerdictInconclusive, Reason: "no gateway evidence found"},
		Detection:   VerdictDetail{Verdict: VerdictFail},
		Response:    VerdictDetail{Verdict: VerdictUnsupported, Reason: "no response-evidence integration exists in this phase"},
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := string(data)
	for _, want := range []string{`"expectation"`, `"observation"`, `"prevention"`, `"detection"`, `"response"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("got %s, want it to contain %s", raw, want)
		}
	}
	if strings.Contains(raw, `"evidence"`) {
		t.Fatalf("got %s, want \"evidence\" omitted when nil", raw)
	}
}

func TestWebGWVerdict_HasExactlyFiveStates(t *testing.T) {
	states := []WebGWVerdict{VerdictPass, VerdictFail, VerdictInconclusive, VerdictUnsupported, VerdictNotApplicable}
	seen := make(map[WebGWVerdict]bool)
	for _, s := range states {
		if seen[s] {
			t.Fatalf("duplicate verdict constant value %q", s)
		}
		seen[s] = true
	}
	if len(seen) != 5 {
		t.Fatalf("got %d distinct verdict states, want 5", len(seen))
	}
}
