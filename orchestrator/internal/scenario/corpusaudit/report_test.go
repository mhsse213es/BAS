package corpusaudit

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestAlreadyCatalogued_TrueForHandAuthoredEntry(t *testing.T) {
	// "" / "default" is a real hand-authored entry (execclass.go) -- the
	// BitLocker posture check.
	if !AlreadyCatalogued("", "default") {
		t.Error("expected the hand-authored \"\"/\"default\" entry to be recognized as catalogued")
	}
}

func TestAlreadyCatalogued_FalseForUnknownPair(t *testing.T) {
	if AlreadyCatalogued("T9999", "nonsense_action_key") {
		t.Error("expected an unknown pair to NOT be catalogued")
	}
}

func TestBuildReport_CountsBySourceAndStatus(t *testing.T) {
	items := []ClassifiedItem{
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{Source: "art", Reachable: true}}, Status: StatusClassified},
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{Source: "art", Reachable: false}}, Status: StatusUnresolved},
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{Source: "art", Reachable: true}}, Status: StatusAlreadyHandAuthored},
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{Source: "caldera", Reachable: true}}, Status: StatusClassified},
	}
	r := BuildReport(items)

	if r.ART.Discovered != 3 {
		t.Errorf("ART.Discovered = %d, want 3", r.ART.Discovered)
	}
	if r.ART.Reachable != 2 {
		t.Errorf("ART.Reachable = %d, want 2", r.ART.Reachable)
	}
	if r.ART.Classified != 2 { // StatusClassified + StatusAlreadyHandAuthored both count as classified
		t.Errorf("ART.Classified = %d, want 2", r.ART.Classified)
	}
	if r.ART.Unresolved != 1 {
		t.Errorf("ART.Unresolved = %d, want 1", r.ART.Unresolved)
	}
	if r.Caldera.Discovered != 1 || r.Caldera.Classified != 1 {
		t.Errorf("Caldera counts wrong: %+v", r.Caldera)
	}
}

func TestBuildReport_DestructiveCandidatesAndManuallyReviewed(t *testing.T) {
	items := []ClassifiedItem{
		// a human-confirmed destructive item: went through reviewed-decisions merge
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{Source: "art", Reachable: true}}, Status: StatusClassified, Class: scenario.ClassDestructive},
		// an unresolved item: flagged by destructiveguard, no reviewed decision yet
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{Source: "art", Reachable: true}}, Status: StatusUnresolved},
		// a plain non_destructive promotion: not a destructive candidate at all
		{KeyedItem: KeyedItem{DiscoveredItem: DiscoveredItem{Source: "art", Reachable: true}}, Status: StatusClassified, Class: scenario.ClassNonDestructive},
	}
	r := BuildReport(items)
	if r.ART.DestructiveCandidates != 2 {
		t.Errorf("DestructiveCandidates = %d, want 2 (1 reviewed-destructive + 1 unresolved)", r.ART.DestructiveCandidates)
	}
	if r.ART.ManuallyReviewed != 1 {
		t.Errorf("ManuallyReviewed = %d, want 1", r.ART.ManuallyReviewed)
	}
}
