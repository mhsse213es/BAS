package networkpath

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
)

func TestHopResult_SerializesWithCamelCaseKeys(t *testing.T) {
	hop := HopResult{FromZone: "a", ToZone: "b", State: cloudgraph.Unknown, RouteDeclared: true}
	data, err := json.Marshal(hop)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := string(data)
	for _, want := range []string{`"fromZone"`, `"toZone"`, `"state"`, `"routeDeclared"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("got %s, want it to contain %s -- every other API-facing type in this codebase uses camelCase json tags", raw, want)
		}
	}
	for _, unwanted := range []string{`"FromZone"`, `"ToZone"`, `"RouteDeclared"`} {
		if strings.Contains(raw, unwanted) {
			t.Fatalf("got %s, want it NOT to contain PascalCase key %s", raw, unwanted)
		}
	}
}

func TestPathResult_SerializesWithCamelCaseKeys(t *testing.T) {
	result := PathResult{State: cloudgraph.Unknown, Confidence: "low", Hops: []HopResult{}}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := string(data)
	for _, want := range []string{`"state"`, `"confidence"`, `"hops"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("got %s, want it to contain %s", raw, want)
		}
	}
	if strings.Contains(raw, `"Confidence"`) || strings.Contains(raw, `"Hops"`) {
		t.Fatalf("got %s, want no PascalCase keys", raw)
	}
}
