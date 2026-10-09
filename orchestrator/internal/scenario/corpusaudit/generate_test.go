package corpusaudit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestWriteGeneratedJSON_ProducesValidSortedJSON(t *testing.T) {
	items := []ClassifiedItem{
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{TechniqueID: "T1082", Command: "whoami"}, ActionKey: "whoami_test"},
			Status: StatusClassified, Class: scenario.ClassNonDestructive, DestructiveAction: "whoami_test", BlastRadius: "read-only identity query"},
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{TechniqueID: "T1490", Command: "vssadmin delete shadows /all"}, ActionKey: "vss_delete_test"},
			Status: StatusClassified, Class: scenario.ClassDestructive, DestructiveAction: "vss_delete_test", BlastRadius: "deletes real shadow copies"},
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{TechniqueID: "T9999", Command: "irrelevant"}, ActionKey: "still_unresolved"},
			Status: StatusUnresolved},
	}
	var buf bytes.Buffer
	if err := WriteGeneratedJSON(&buf, items); err != nil {
		t.Fatalf("WriteGeneratedJSON: %v", err)
	}
	var got []generatedEntry
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("generated file is not valid JSON: %v\n---\n%s", err, buf.String())
	}
	if len(got) != 2 {
		t.Fatalf("expected exactly the 2 classified entries (unresolved excluded), got %d: %+v", len(got), got)
	}
	// Sorted by (technique_id, action_key): T1082 before T1490.
	if got[0].T != "T1082" || got[0].A != "whoami_test" || got[0].C != string(scenario.ClassNonDestructive) {
		t.Errorf("entry 0 wrong: %+v", got[0])
	}
	if got[1].T != "T1490" || got[1].A != "vss_delete_test" || got[1].C != string(scenario.ClassDestructive) {
		t.Errorf("entry 1 wrong: %+v", got[1])
	}
	if strings.Contains(buf.String(), "T9999") {
		t.Error("expected an unresolved item to be excluded from the generated catalog entirely")
	}
}

func TestWriteReportMarkdown_FormatsRealCounts(t *testing.T) {
	r := CoverageReport{
		ART:     SourceCounts{Discovered: 500, Reachable: 480, Classified: 470, DestructiveCandidates: 30, ManuallyReviewed: 28, Unresolved: 2},
		Caldera: SourceCounts{Discovered: 2200, Reachable: 2100, Classified: 2080, DestructiveCandidates: 50, ManuallyReviewed: 45, Unresolved: 5},
	}
	var buf bytes.Buffer
	if err := WriteReportMarkdown(&buf, r); err != nil {
		t.Fatalf("WriteReportMarkdown: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"ART:", "discovered: 500", "unresolved: 2", "collisions: 0", "Caldera:", "discovered: 2200", "unresolved: 5"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}
