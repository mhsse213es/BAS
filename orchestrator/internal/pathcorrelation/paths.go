package pathcorrelation

import (
	"fmt"
	"sort"

	"github.com/audspect/bas/internal/attackpath"
)

// Path-weight constants for the DetectionCoverageScore formula (see
// correlate.go). The Domain-Admin path always outweighs any single crown
// jewel; a crown jewel reachable from more entry hosts weighs more, capped
// so one extremely exposed jewel cannot swamp the score.
const (
	pathWeightDA          = 40.0
	crownJewelBaseWeight  = 15.0
	crownJewelEntryWeight = 3.0
	crownJewelEntryCap    = 5
)

// DefaultPaths builds this slice's default correlated-path set from an
// already-computed Summary: the Domain-Admin path (if any) plus one
// representative shortest path to each reachable crown jewel. A future
// caller (e.g. Exposure Explorer) can construct its own []AttackPath and
// call Correlate directly, bypassing this helper.
func DefaultPaths(g *attackpath.Graph, s attackpath.Summary) []AttackPath {
	var paths []AttackPath
	if len(s.ShortestDAPath) > 0 {
		paths = append(paths, AttackPath{
			Label:  fmt.Sprintf("Shortest path to Domain Admin (from %s)", s.MaxBlastEntry),
			Edges:  s.ShortestDAPath,
			Weight: pathWeightDA,
		})
	}

	var hosts []string
	for _, n := range g.Nodes() {
		if n.Kind == attackpath.KindHost {
			hosts = append(hosts, n.ID)
		}
	}
	sort.Strings(hosts)

	for _, cj := range s.ReachableCrownJewels() {
		for _, h := range hosts {
			p := g.ShortestPath(h, cj.Node)
			if len(p) == 0 || len(p) != cj.MinHops {
				continue
			}
			entries := cj.EntryHosts
			if entries > crownJewelEntryCap {
				entries = crownJewelEntryCap
			}
			paths = append(paths, AttackPath{
				Label:  fmt.Sprintf("Path to crown jewel %s (%s), from %s", cj.Tag, cj.Node, h),
				Edges:  p,
				Weight: crownJewelBaseWeight + crownJewelEntryWeight*float64(entries),
			})
			break
		}
	}
	return paths
}
