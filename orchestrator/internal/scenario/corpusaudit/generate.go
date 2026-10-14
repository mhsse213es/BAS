package corpusaudit

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// generatedEntry is one execclass_generated.json row. The short JSON tags keep
// the embedded blob compact; internal/scenario's embed loader decodes the same
// shape. Only StatusClassified items are emitted -- StatusAlreadyHandAuthored
// items are already in execclass.go, and StatusUnresolved items must NEVER
// appear in a committed catalog file.
type generatedEntry struct {
	T string `json:"t"` // technique_id
	A string `json:"a"` // action_key
	C string `json:"c"` // execution class
	D string `json:"d"` // destructive action
	B string `json:"b"` // blast radius
}

// WriteGeneratedJSON writes execclass_generated.json: the classified catalog as
// a compact JSON array, loaded via //go:embed in internal/scenario rather than
// emitted as ~thousands of Go string literals. The literal form made
// garble -literals rewrite tens of thousands of literals in one package and
// hang the release build; an embedded blob is not a source literal, so the
// obfuscator leaves it alone. Entries are sorted (technique_id, action_key) for
// a stable diff.
func WriteGeneratedJSON(w io.Writer, items []ClassifiedItem) error {
	var entries []generatedEntry
	for _, it := range items {
		if it.Status != StatusClassified {
			continue
		}
		entries = append(entries, generatedEntry{it.TechniqueID, it.ActionKey, string(it.Class), it.DestructiveAction, it.BlastRadius})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].T != entries[j].T {
			return entries[i].T < entries[j].T
		}
		return entries[i].A < entries[j].A
	})
	b, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// WriteReportMarkdown writes the coverage report in the exact format the
// design doc specifies, split by source, with real counts from the run
// that produced r -- never hard-coded.
func WriteReportMarkdown(w io.Writer, r CoverageReport) error {
	_, err := fmt.Fprintf(w, "ART:\n"+
		"  discovered: %d\n  reachable: %d\n  classified: %d\n"+
		"  destructive candidates: %d\n  manually reviewed: %d\n  unresolved: %d\n  collisions: %d\n\n"+
		"Caldera:\n"+
		"  discovered: %d\n  reachable: %d\n  classified: %d\n"+
		"  destructive candidates: %d\n  manually reviewed: %d\n  unresolved: %d\n  collisions: %d\n",
		r.ART.Discovered, r.ART.Reachable, r.ART.Classified, r.ART.DestructiveCandidates, r.ART.ManuallyReviewed, r.ART.Unresolved, r.ART.Collisions,
		r.Caldera.Discovered, r.Caldera.Reachable, r.Caldera.Classified, r.Caldera.DestructiveCandidates, r.Caldera.ManuallyReviewed, r.Caldera.Unresolved, r.Caldera.Collisions,
	)
	return err
}
