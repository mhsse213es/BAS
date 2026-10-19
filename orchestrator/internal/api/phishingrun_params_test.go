package api

import (
	"testing"

	"github.com/audspect/bas/internal/phishcatalog"
)

// Every scenario the registry can run must have a parameter schema entry, even
// when it takes no parameters. Otherwise the library cannot show its form.
func TestPhishingRunParams_EveryExecutableHasSchema(t *testing.T) {
	cat, err := phishcatalog.AudspectPhishingCatalog()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	for _, sc := range cat {
		if _, ok := LookupPhishingRunExecutor(sc.ID); !ok {
			continue
		}
		if _, ok := phishingRunParams[sc.ID]; !ok {
			t.Errorf("%s is executable but has no parameter schema entry", sc.ID)
		}
	}
}

func TestPhishingRunParams_RequiredFieldsPerScenario(t *testing.T) {
	cases := map[string][]string{
		"PH-DET-002":  {"executionId", "targetId"},
		"PH-ID-001":   {"executionId"},
		"PH-ID-002":   {"runId", "clientIds"},
		"PH-IR-003":   {"runId"},
		"PH-ID-003":   {"userIds"},
		"PH-ID-004":   {"userId", "threshold", "windowSeconds"},
		"PH-ID-005":   {"userId", "windowSeconds"},
		"PH-EVA-002":  {"emailGwRunId", "relayEmailGwRunId"},
		"PH-CHN-004":  {"organizerUserId", "attendeeEmail"},
		"PH-AUTH-002": {"emailGwRunId"},
		"PH-CHN-005":  {"emailGwRunId"},
	}
	for id, want := range cases {
		var got []string
		for _, p := range phishingRunParams[id] {
			if p.Required {
				got = append(got, p.Name)
			}
		}
		if len(got) != len(want) {
			t.Errorf("%s: required=%v, want %v", id, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s: required=%v, want %v", id, got, want)
				break
			}
		}
	}
}

// The library entry carries its schema, so the UI renders the form from the
// server's definition and never hardcodes one.
func TestPhishingLibraryEntries_CarryParameterSchema(t *testing.T) {
	cat := []phishcatalog.Scenario{{ID: "PH-DET-002", Name: "d"}}
	entries := phishingLibraryEntries(cat, poolOnly())
	if len(entries) != 1 || len(entries[0].Parameters) != 2 {
		t.Fatalf("entries = %+v, want PH-DET-002 with 2 parameters", entries)
	}
}
