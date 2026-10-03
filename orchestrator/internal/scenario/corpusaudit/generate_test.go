package corpusaudit

import (
	"bytes"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestWriteGeneratedGo_ProducesValidGoSyntax(t *testing.T) {
	items := []ClassifiedItem{
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{TechniqueID: "T1082", Command: "whoami"}, ActionKey: "whoami_test"},
			Status: StatusClassified, Class: scenario.ClassNonDestructive, DestructiveAction: "whoami_test", BlastRadius: "read-only identity query"},
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{TechniqueID: "T1490", Command: "vssadmin delete shadows /all"}, ActionKey: "vss_delete_test"},
			Status: StatusClassified, Class: scenario.ClassDestructive, DestructiveAction: "vss_delete_test", BlastRadius: "deletes real shadow copies"},
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{TechniqueID: "T9999", Command: "irrelevant"}, ActionKey: "still_unresolved"},
			Status: StatusUnresolved},
	}
	var buf bytes.Buffer
	if err := WriteGeneratedGo(&buf, items); err != nil {
		t.Fatalf("WriteGeneratedGo: %v", err)
	}
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "execclass_generated.go", buf.String(), 0); err != nil {
		t.Fatalf("generated file is not valid Go: %v\n---\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "package scenario") {
		t.Error("expected package scenario declaration")
	}
	if !strings.Contains(out, "DO NOT EDIT") {
		t.Error("expected a DO NOT EDIT header")
	}
	if !strings.Contains(out, `"T1082"`) || !strings.Contains(out, `"whoami_test"`) {
		t.Error("expected the classified non_destructive entry to appear")
	}
	if !strings.Contains(out, `"T1490"`) || !strings.Contains(out, `"vss_delete_test"`) {
		t.Error("expected the classified destructive entry to appear")
	}
	if strings.Contains(out, "T9999") {
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
	for _, want := range []string{"ART:", "discovered: 500", "unresolved: 2", "Caldera:", "discovered: 2200", "unresolved: 5"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}
