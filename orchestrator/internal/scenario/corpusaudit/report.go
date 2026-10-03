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
	// Collisions counts items DeriveActionKeys excluded entirely because
	// two genuinely different commands shared one (technique_id, slug,
	// executor) identity (see identity.go's CollisionError). These are
	// NOT folded into Unresolved: at runtime a missing catalog entry
	// already fails closed to "destructive"/unclassified (blocked, not
	// silently permitted), so a collision is a corpus-identity-uniqueness
	// defect -- an availability gap, not a safety gap -- and is reported
	// separately so it stays visible rather than silently dropped.
	Collisions int
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
// collisions is DeriveActionKeys' second return value, passed straight
// through from the same run that produced items; every distinct item it
// names (deduped, since one N-way collision produces C(N,2) pairwise
// CollisionErrors for only N items) is counted as Discovered/Reachable
// (it was a real corpus item) and as Collisions, per source.
func BuildReport(items []ClassifiedItem, collisions []CollisionError) CoverageReport {
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

	type itemKey struct{ source, tech, name, executor, command string }
	seen := map[itemKey]bool{}
	for _, col := range collisions {
		for _, it := range [2]DiscoveredItem{col.ItemA, col.ItemB} {
			k := itemKey{it.Source, col.TechniqueID, it.Name, it.Executor, it.Command}
			if seen[k] {
				continue
			}
			seen[k] = true
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
			c.Collisions++
		}
	}
	return r
}
