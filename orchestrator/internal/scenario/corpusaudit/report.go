package corpusaudit

import "github.com/audspect/bas/internal/scenario"

// Status is where a KeyedItem landed after triage.
type Status string

const (
	StatusAlreadyHandAuthored Status = "already_hand_authored"
	StatusClassified          Status = "classified"
	StatusUnresolved          Status = "unresolved"
)

// ClassifiedItem is a KeyedItem after triage against the hand-authored
// catalog, destructiveguard, and the reviewed-decisions file (Task 4).
type ClassifiedItem struct {
	KeyedItem
	Status            Status
	Class             scenario.ExecutionClass // meaningful only when Status == StatusClassified
	DestructiveAction string
	BlastRadius       string
}

// AlreadyCatalogued reports whether (techniqueID, actionKey) already
// resolves via the hand-authored catalog. Reuses the exact sentinel check
// orchestrator/cmd/probeclassify already established (comparing
// DestructiveAction against the "unclassified" fail-closed sentinel) --
// never re-derives catalog internals.
func AlreadyCatalogued(techniqueID, actionKey string) bool {
	return scenario.ResolveExecutionClass(techniqueID, actionKey).DestructiveAction != "unclassified"
}

type SourceCounts struct {
	Discovered            int
	Reachable             int
	Classified            int
	DestructiveCandidates int
	ManuallyReviewed      int
	Unresolved            int
}

type CoverageReport struct {
	ART     SourceCounts
	Caldera SourceCounts
}

// BuildReport tallies real counts from the live classification run --
// never hard-coded. DestructiveCandidates counts every item that was ever
// flagged by destructiveguard, whether a human has resolved it yet
// (Status == StatusClassified with a non-NonDestructive Class) or not
// (Status == StatusUnresolved). ManuallyReviewed counts only the former.
func BuildReport(items []ClassifiedItem) CoverageReport {
	var r CoverageReport
	for _, it := range items {
		var c *SourceCounts
		switch it.Source {
		case "art":
			c = &r.ART
		case "caldera":
			c = &r.Caldera
		default:
			continue
		}
		c.Discovered++
		if it.Reachable {
			c.Reachable++
		}
		switch it.Status {
		case StatusClassified, StatusAlreadyHandAuthored:
			c.Classified++
		case StatusUnresolved:
			c.Unresolved++
			c.DestructiveCandidates++
		}
		if it.Status == StatusClassified && it.Class != scenario.ClassNonDestructive {
			c.DestructiveCandidates++
			c.ManuallyReviewed++
		}
	}
	return r
}
