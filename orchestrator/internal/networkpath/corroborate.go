package networkpath

import (
	"strings"

	"github.com/audspect/bas/internal/attackpath"
)

// lateralEdgeKinds restricts corroboration to the identity domain's own
// host-to-host lateral-movement edges -- never ACL-abuse/delegation
// edges, which aren't network-reachability evidence.
var lateralEdgeKinds = map[attackpath.EdgeKind]bool{
	attackpath.EdgeSMB:   true,
	attackpath.EdgeWinRM: true,
	attackpath.EdgeRDP:   true,
}

// CorroborateHop looks for an attackpath edge between fromHost and
// toHost (normalized via attackpath.NormalizeHostKey, since Node.ID is
// not guaranteed pre-normalized) restricted to SMB/WinRM/RDP. Absence of
// any match, or of an attackpath graph at all, returns an empty slice,
// never an error -- corroboration is optional and fails open, and never
// changes a hop's own PathState.
func CorroborateHop(g *attackpath.Graph, fromHost, toHost string) []CorroboratingEvidence {
	if g == nil {
		return nil
	}
	from := attackpath.NormalizeHostKey(fromHost)
	to := attackpath.NormalizeHostKey(toHost)
	var out []CorroboratingEvidence
	for _, e := range g.Edges() {
		if !lateralEdgeKinds[e.Kind] {
			continue
		}
		if attackpath.NormalizeHostKey(e.From) != from || attackpath.NormalizeHostKey(e.To) != to {
			continue
		}
		out = append(out, CorroboratingEvidence{Source: "attackpath", EdgeKind: string(e.Kind), Note: "identity-domain lateral-movement edge exists between these hosts -- corroborating, not authoritative"})
	}
	return out
}

// CorroborateSegmentation cites an attackpath SegmentationViolation
// whose FromSegment/ToSegment name-match the given zone pair -- a
// loose, best-effort note. attackpath.Segment has no guaranteed
// correspondence to this phase's declared zones, so a mismatch or
// absence is silent, never an error.
func CorroborateSegmentation(g *attackpath.Graph, fromZone, toZone string) []CorroboratingEvidence {
	if g == nil {
		return nil
	}
	var out []CorroboratingEvidence
	for _, v := range g.SegmentationViolations() {
		if !strings.EqualFold(v.FromSegment, fromZone) || !strings.EqualFold(v.ToSegment, toZone) {
			continue
		}
		out = append(out, CorroboratingEvidence{Source: "attackpath", EdgeKind: string(v.Kind), Note: "identity-domain segmentation violation recorded between these zone-named segments -- corroborating, not authoritative"})
	}
	return out
}
