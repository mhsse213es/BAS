package attackpath

import "sort"

// Summary is the report-ready output of the attack-path engine: the headline
// AttackPathScore plus the supporting analytics the report and dashboard render.
type Summary struct {
	AttackPathScore      int                     `json:"attackPathScore"` // 0..100, HIGHER = better (less exposed)
	Band                 string                  `json:"band"`            // Critical|High|Medium|Low (risk band, inverse of score)
	Hosts                int                     `json:"hosts"`
	Users                int                     `json:"users"`
	Groups               int                     `json:"groups"`
	Edges                int                     `json:"edges"`
	DomainCompromise     bool                    `json:"domainCompromise"`     // some host can reach a Domain Admin / Tier-0 target
	LateralMovementBand  string                  `json:"lateralMovementBand"`  // Critical|High|Medium|Low
	AvgBlastRadius       float64                 `json:"avgBlastRadius"`       // avg other-hosts compromisable per entry
	MaxBlastRadius       int                     `json:"maxBlastRadius"`       // worst single entry host
	MaxBlastEntry        string                  `json:"maxBlastEntry"`        // that host id
	SegmentationViols    []SegmentationViolation `json:"segmentationViolations"`
	CrownJewels          []CrownJewelExposure    `json:"crownJewels"`
	ChokePoints          []ChokePoint            `json:"chokePoints"`
	ShortestDAPath       []Edge                  `json:"shortestDomainAdminPath"` // representative worst-case path to DA (nil if none)
	ShortestDADifficulty Difficulty              `json:"shortestDomainAdminDifficulty"`
	ScoreDrivers         []ScoreDriver           `json:"scoreDrivers"`
	RelationshipCounts   map[string]int          `json:"relationshipCounts"` // keyed by EdgeKind string value
}

// ScoreDriver is one weighted category's contribution to the AttackPathScore
// deficit. Deficit is the real number subtracted from 100 for this category --
// never an invented "bonus"; the scoring model is pure-deficit (100 - sum(deficits)).
type ScoreDriver struct {
	Label   string  `json:"label"`
	Deficit float64 `json:"deficit"` // points subtracted from 100; 0 = no deficit in this category
}

// score weights (deficits subtracted from 100). Tuned so a flat, fully meshed
// network with domain compromise and segmentation failures lands deep in the
// red, while a well-segmented fleet with no DA path stays high.
const (
	wDomainCompromise = 30 // any host → Domain Admin reachable
	wLateralMax       = 35 // proportional to average blast radius
	wCrownJewel       = 20 // crown jewels reachable from the fleet
	wSegmentation     = 15 // segment-crossing lateral edges
)

// Analyze runs the full attack-path analysis and returns the report Summary.
// AttackPathScore is 100 minus weighted exposure deficits, clamped to [0,100].
func (g *Graph) Analyze() Summary {
	s := Summary{
		Hosts: g.countKind(KindHost),
		Users: g.countKind(KindUser),
		Groups: g.countKind(KindGroup),
		Edges: g.EdgeCount(),
	}

	hosts := g.hostIDs()
	s.RelationshipCounts = map[string]int{}
	for _, e := range g.Edges() {
		s.RelationshipCounts[string(e.Kind)]++
	}
	s.LateralMovementBand = g.LateralMovementBand()
	s.SegmentationViols = g.SegmentationViolations()
	s.CrownJewels = g.CrownJewelExposures()
	s.ChokePoints = g.ChokePoints()

	// blast radius stats
	totalBlast := 0
	for _, h := range hosts {
		b := g.BlastRadius(h)
		totalBlast += b
		if b > s.MaxBlastRadius {
			s.MaxBlastRadius = b
			s.MaxBlastEntry = h
		}
	}
	if len(hosts) > 0 {
		s.AvgBlastRadius = round2(float64(totalBlast) / float64(len(hosts)))
	}

	// domain compromise + representative worst-case path (the shortest DA path
	// from the host with the largest blast radius, else the first host with one)
	hv := g.highValueTargets()
	if len(hv) > 0 {
		if s.MaxBlastEntry != "" {
			s.ShortestDAPath = g.ShortestPathToDomainAdmin(s.MaxBlastEntry)
		}
		if s.ShortestDAPath == nil {
			for _, h := range hosts {
				if p := g.ShortestPathToDomainAdmin(h); p != nil {
					s.ShortestDAPath = p
					break
				}
			}
		}
		s.DomainCompromise = s.ShortestDAPath != nil
	}
	s.ShortestDADifficulty = PathDifficulty(s.ShortestDAPath)

	// ---- deficits ----
	deficit := 0.0
	var drivers []ScoreDriver

	dcDeficit := 0.0
	if s.DomainCompromise {
		dcDeficit = wDomainCompromise
	}
	deficit += dcDeficit
	drivers = append(drivers, ScoreDriver{Label: "Domain Admin path reachable", Deficit: dcDeficit})

	// lateral movement: fraction of the fleet an average entry can reach
	lateralDeficit := 0.0
	if denom := float64(maxInt(len(hosts)-1, 1)); len(hosts) > 0 {
		frac := s.AvgBlastRadius / denom
		if frac > 1 {
			frac = 1
		}
		lateralDeficit = frac * wLateralMax
	}
	deficit += lateralDeficit
	drivers = append(drivers, ScoreDriver{Label: "Lateral movement exposure", Deficit: round2(lateralDeficit)})

	// crown jewels: fraction of tagged jewels reachable from any host
	crownJewelDeficit := 0.0
	if len(s.CrownJewels) > 0 {
		reach := 0
		for _, cj := range s.CrownJewels {
			if cj.Reachable {
				reach++
			}
		}
		crownJewelDeficit = (float64(reach) / float64(len(s.CrownJewels))) * wCrownJewel
	}
	deficit += crownJewelDeficit
	drivers = append(drivers, ScoreDriver{Label: "Crown jewel exposure", Deficit: round2(crownJewelDeficit)})

	// segmentation: saturating penalty on cross-segment lateral edges
	segDeficit := 0.0
	if v := len(s.SegmentationViols); v > 0 {
		frac := float64(v) / float64(v+3) // 1 viol→0.25, 3→0.5, 9→0.75
		segDeficit = frac * wSegmentation
	}
	deficit += segDeficit
	drivers = append(drivers, ScoreDriver{Label: "Segmentation violations", Deficit: round2(segDeficit)})

	s.ScoreDrivers = drivers

	score := 100 - int(deficit+0.5)
	score = max(score, 0)
	score = min(score, 100)
	s.AttackPathScore = score
	s.Band = scoreBand(score)
	return s
}

// scoreBand converts a higher-is-better score into a risk band.
func scoreBand(score int) string {
	switch {
	case score >= 80:
		return "Low"
	case score >= 60:
		return "Medium"
	case score >= 40:
		return "High"
	default:
		return "Critical"
	}
}

func (g *Graph) countKind(k NodeKind) int {
	n := 0
	for _, node := range g.nodes {
		if node.Kind == k {
			n++
		}
	}
	return n
}

// TopChokePoints returns at most n choke points (already sorted).
func (s Summary) TopChokePoints(n int) []ChokePoint {
	if len(s.ChokePoints) <= n {
		return s.ChokePoints
	}
	return s.ChokePoints[:n]
}

// ReachableCrownJewels returns crown jewels that are reachable, worst first.
func (s Summary) ReachableCrownJewels() []CrownJewelExposure {
	var out []CrownJewelExposure
	for _, cj := range s.CrownJewels {
		if cj.Reachable {
			out = append(out, cj)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EntryHosts != out[j].EntryHosts {
			return out[i].EntryHosts > out[j].EntryHosts
		}
		return out[i].MinHops < out[j].MinHops
	})
	return out
}
