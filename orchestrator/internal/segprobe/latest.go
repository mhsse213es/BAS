package segprobe

import "github.com/audspect/bas/internal/segprobe/runstore"

// LatestCompletedPerPack picks, for each pack, the newest completed run from runs. The input must be newest
// first, as runstore.Store.List returns it. A pack with no completed run contributes nothing.
func LatestCompletedPerPack(runs []runstore.Run) []runstore.Run {
	seen := make(map[string]bool)
	var out []runstore.Run
	for _, r := range runs {
		if r.Status != "completed" || seen[r.PackID] {
			continue
		}
		seen[r.PackID] = true
		out = append(out, r)
	}
	return out
}
