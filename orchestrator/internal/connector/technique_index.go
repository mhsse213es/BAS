package connector

import (
	"log"
	"sort"
	"strings"

	"github.com/audspect/bas/internal/scenario"
)

// buildTechniqueIndex maps each ATT&CK technique ID to the profile names
// that declare it via TechniqueIDs, sorted for deterministic first-match
// resolution. Profiles with no TechniqueIDs (e.g. abstract base profiles
// meant only to be extend-ed) contribute nothing.
func buildTechniqueIndex(profiles map[string]*scenario.DetectionProfile) map[string][]string {
	idx := make(map[string][]string)
	for name, p := range profiles {
		for _, tid := range p.TechniqueIDs {
			up := strings.ToUpper(tid)
			idx[up] = append(idx[up], name)
		}
	}
	for tid := range idx {
		sort.Strings(idx[tid])
	}
	return idx
}

// resolveProfile returns the profile name to attach for a technique, or ""
// if none match. Exact match only -- T1562.001 never matches a profile
// declaring only T1562. When multiple profiles claim the same technique,
// the first by sorted name wins and every candidate is logged, surfacing
// the conflict for a human to resolve rather than guessing silently.
func resolveProfile(idx map[string][]string, techID string) string {
	candidates := idx[strings.ToUpper(techID)]
	if len(candidates) == 0 {
		return ""
	}
	if len(candidates) > 1 {
		log.Printf("[connector/gen] technique %s matches multiple detection profiles %v -- attaching %q, review for consolidation", techID, candidates, candidates[0])
	}
	return candidates[0]
}
