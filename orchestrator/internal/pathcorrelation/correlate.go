package pathcorrelation

import (
	"context"
	"fmt"
	"sort"

	"github.com/audspect/bas/internal/attackpath"
)

// gapFactor weights for VerifiedStatus, used both by scoring and by gap
// ranking. Gap (a rule exists, never proven to fire) ranks above Unknown (no
// rule exists at all) because it is the more immediately actionable of the
// two — tune here, not in every call site.
const (
	weightGap     = 1.0
	weightUnknown = 0.6
	weightPartial = 0.4
	weightCovered = 0.0

	gapPriorityCritical = 0.5
	gapPriorityHigh     = 0.25
	gapPriorityMedium   = 0.10
)

type edgeKey struct {
	From, To string
	Kind     attackpath.EdgeKind
}

func edgeKeyOf(e attackpath.Edge) edgeKey { return edgeKey{e.From, e.To, e.Kind} }

// Correlate is the sole entry point: given an already-built graph/summary
// and a set of paths to annotate (see DefaultPaths), it computes per-edge
// detection status, a weighted DetectionCoverageScore, and prioritized gaps.
func Correlate(
	ctx context.Context,
	g *attackpath.Graph,
	s attackpath.Summary,
	paths []AttackPath,
	mapper EdgeTechniqueMapper,
	runs RunLookup,
	rules RuleLibrary,
) (AttackPathCorrelation, error) {
	if mapper == nil {
		mapper = DefaultEdgeTechniqueMapper{}
	}

	canonical := map[edgeKey]attackpath.Edge{}
	for _, p := range paths {
		for _, e := range p.Edges {
			canonical[edgeKeyOf(e)] = e
		}
	}
	for _, cp := range s.ChokePoints {
		for _, e := range g.EdgesTo(cp.Node) {
			canonical[edgeKeyOf(e)] = e
		}
	}

	statuses := make(map[edgeKey]DetectionStatus, len(canonical))
	for key, e := range canonical {
		st, err := statusFor(ctx, g, e, mapper, runs, rules)
		if err != nil {
			return AttackPathCorrelation{}, fmt.Errorf("pathcorrelation: status for edge %+v: %w", e, err)
		}
		statuses[key] = st
	}
	annotate := func(e attackpath.Edge) AnnotatedEdge {
		return AnnotatedEdge{Edge: e, Status: statuses[edgeKeyOf(e)]}
	}

	var annotatedPaths []AnnotatedPath
	for _, p := range paths {
		ap := AnnotatedPath{Label: p.Label, Weight: p.Weight}
		for _, e := range p.Edges {
			ap.Edges = append(ap.Edges, annotate(e))
		}
		ap.WeakestLink = weakestLink(ap.Edges)
		annotatedPaths = append(annotatedPaths, ap)
	}

	var annotatedChoke []AnnotatedChokePoint
	for _, cp := range s.ChokePoints {
		var incoming []AnnotatedEdge
		for _, e := range g.EdgesTo(cp.Node) {
			incoming = append(incoming, annotate(e))
		}
		annotatedChoke = append(annotatedChoke, AnnotatedChokePoint{
			ChokePoint: cp, IncomingEdges: incoming, WeakestLink: weakestLink(incoming),
		})
	}

	gaps := buildGaps(g, s, paths, canonical, statuses)
	stats := buildStatistics(canonical, statuses, gaps)
	score := computeScore(annotatedPaths)

	return AttackPathCorrelation{
		Summary:     summarize(annotatedPaths, stats),
		Score:       score,
		Paths:       annotatedPaths,
		ChokePoints: annotatedChoke,
		Gaps:        gaps,
		Statistics:  stats,
	}, nil
}

// relevantHost returns the graph node ID whose telemetry would observe this
// edge's technique execution, or "" when neither endpoint is a host (e.g.
// MemberOf, a pure user/group relationship) — RunLookup then searches
// environment-wide only. For a session edge the technique executes on the
// host holding the session (From); for every other kind it executes on the
// target being reached (To), falling back to From if To is not a host node.
func relevantHost(g *attackpath.Graph, e attackpath.Edge) string {
	if e.Kind == attackpath.EdgeHasSession {
		if n, ok := g.Node(e.From); ok && n.Kind == attackpath.KindHost {
			return e.From
		}
		return ""
	}
	if n, ok := g.Node(e.To); ok && n.Kind == attackpath.KindHost {
		return e.To
	}
	if n, ok := g.Node(e.From); ok && n.Kind == attackpath.KindHost {
		return e.From
	}
	return ""
}

func statusFor(ctx context.Context, g *attackpath.Graph, e attackpath.Edge, mapper EdgeTechniqueMapper, runs RunLookup, rules RuleLibrary) (DetectionStatus, error) {
	techs := mapper.Techniques(e.Kind)
	if len(techs) == 0 {
		return DetectionStatus{Expected: ExpectedGap, Verified: VerifiedUnknown, Confidence: ConfidenceUnknown}, nil
	}

	host := relevantHost(g, e)
	foundCount, expectedCoveredCount := 0, 0
	bestConfidence := ConfidenceUnknown
	var ev Evidence
	for _, t := range techs {
		if rules != nil {
			if rs := rules.RulesByTechnique(t.TechniqueID); len(rs) > 0 {
				expectedCoveredCount++
				for _, r := range rs {
					ev.RuleIDs = append(ev.RuleIDs, r.ID)
				}
			}
		}
		if runs == nil {
			continue
		}
		res, found, err := runs.VerifiedDetection(ctx, t.TechniqueID, host)
		if err != nil {
			return DetectionStatus{}, err
		}
		if !found {
			continue
		}
		foundCount++
		if confidenceRank(res.Confidence) > confidenceRank(bestConfidence) {
			bestConfidence = res.Confidence
		}
		ev.RunID = res.Evidence.RunID
		ev.Provider = res.Evidence.Provider
		ev.VerifiedAt = res.Evidence.VerifiedAt
		ev.AlertIDs = append(ev.AlertIDs, res.Evidence.AlertIDs...)
	}

	st := DetectionStatus{Techniques: techs, Evidence: ev, Confidence: bestConfidence}
	if expectedCoveredCount > 0 {
		st.Expected = ExpectedCovered
	} else {
		st.Expected = ExpectedGap
	}
	switch {
	case foundCount == len(techs):
		st.Verified = VerifiedCovered
	case foundCount > 0:
		st.Verified = VerifiedPartial
	case expectedCoveredCount > 0:
		st.Verified = VerifiedGap
	default:
		st.Verified = VerifiedUnknown
	}
	return st, nil
}

func confidenceRank(c VerificationConfidence) int {
	switch c {
	case ConfidenceHost:
		return 2
	case ConfidenceEnvironment:
		return 1
	default:
		return 0
	}
}

func gapFactor(v VerifiedStatus) float64 {
	switch v {
	case VerifiedGap:
		return weightGap
	case VerifiedUnknown:
		return weightUnknown
	case VerifiedPartial:
		return weightPartial
	default:
		return weightCovered
	}
}

func maxWeight(techs []TechniqueMapping) float64 {
	m := 0.0
	for _, t := range techs {
		if t.Weight > m {
			m = t.Weight
		}
	}
	return m
}

func weakestLink(edges []AnnotatedEdge) *AnnotatedEdge {
	if len(edges) == 0 {
		return nil
	}
	worst := edges[0]
	worstScore := gapFactor(worst.Status.Verified)
	for _, e := range edges[1:] {
		if f := gapFactor(e.Status.Verified); f > worstScore {
			worst, worstScore = e, f
		}
	}
	return &worst
}

// pathStrength is the best single hop's (1-gapFactor)*criticality along the
// path — the strongest hop dominates, since one well-detected hop is enough
// for the SOC to catch an attacker walking that path (the "broken attack
// chain" framing: a path with high strength is broken, near-zero is silent
// end to end).
func pathStrength(p AnnotatedPath) float64 {
	best := 0.0
	for _, e := range p.Edges {
		if strength := (1 - gapFactor(e.Status.Verified)) * maxWeight(e.Status.Techniques); strength > best {
			best = strength
		}
	}
	return best
}

func computeScore(paths []AnnotatedPath) int {
	var totalWeight, deficitSum float64
	for _, p := range paths {
		if p.Weight <= 0 {
			continue
		}
		totalWeight += p.Weight
		deficitSum += p.Weight * (1 - pathStrength(p))
	}
	if totalWeight == 0 {
		return 100
	}
	score := 100 - int(100*deficitSum/totalWeight+0.5)
	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}
	return score
}

func targetNodes(s attackpath.Summary) []string {
	var out []string
	if s.DomainCompromise && len(s.ShortestDAPath) > 0 {
		out = append(out, s.ShortestDAPath[len(s.ShortestDAPath)-1].To)
	}
	for _, cj := range s.CrownJewels {
		if cj.Reachable {
			out = append(out, cj.Node)
		}
	}
	return out
}

func nearestTargetDistance(g *attackpath.Graph, from string, targets []string) int {
	best := -1
	for _, t := range targets {
		if from == t {
			return 0
		}
		if p := g.ShortestPath(from, t); len(p) > 0 && (best == -1 || len(p) < best) {
			best = len(p)
		}
	}
	if best == -1 {
		return 10 // no reachable target from here — treat as far
	}
	return best
}

func priorityFor(score float64) GapPriority {
	switch {
	case score >= gapPriorityCritical:
		return PriorityCritical
	case score >= gapPriorityHigh:
		return PriorityHigh
	case score >= gapPriorityMedium:
		return PriorityMedium
	default:
		return PriorityLow
	}
}

func gapReason(crossCount, totalPaths, dist int, st DetectionStatus) string {
	verb := "no verified detection"
	switch st.Verified {
	case VerifiedPartial:
		verb = "only partial verified detection"
	case VerifiedUnknown:
		verb = "no detection capability found for this technique"
	}
	return fmt.Sprintf("crossed by %d of %d correlated path(s), %d hop(s) from the nearest high-value target, %s",
		crossCount, totalPaths, dist, verb)
}

func buildGaps(g *attackpath.Graph, s attackpath.Summary, paths []AttackPath, canonical map[edgeKey]attackpath.Edge, statuses map[edgeKey]DetectionStatus) []PrioritizedGap {
	totalPaths := len(paths)
	if totalPaths == 0 {
		totalPaths = 1
	}
	crossCount := map[edgeKey]int{}
	for _, p := range paths {
		seen := map[edgeKey]bool{}
		for _, e := range p.Edges {
			k := edgeKeyOf(e)
			if !seen[k] {
				crossCount[k]++
				seen[k] = true
			}
		}
	}
	targets := targetNodes(s)

	var gaps []PrioritizedGap
	for k, e := range canonical {
		st := statuses[k]
		gf := gapFactor(st.Verified)
		if gf == 0 {
			continue
		}
		freq := float64(crossCount[k]) / float64(totalPaths)
		dist := nearestTargetDistance(g, e.To, targets)
		proximity := 1.0 / (1.0 + float64(dist))
		crit := maxWeight(st.Techniques)
		score := freq * proximity * crit * gf

		gaps = append(gaps, PrioritizedGap{
			Edge:       e,
			Techniques: st.Techniques,
			Priority:   priorityFor(score),
			Reason:     gapReason(crossCount[k], totalPaths, dist, st),
			score:      score,
		})
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].score > gaps[j].score })
	return gaps
}

func buildStatistics(canonical map[edgeKey]attackpath.Edge, statuses map[edgeKey]DetectionStatus, gaps []PrioritizedGap) Statistics {
	var st Statistics
	st.EdgesTotal = len(canonical)
	techRisk := map[string]float64{}
	for k := range canonical {
		s := statuses[k]
		if s.Expected == ExpectedCovered {
			st.ExpectedCovered++
		} else {
			st.ExpectedGap++
		}
		switch s.Verified {
		case VerifiedCovered:
			st.VerifiedCovered++
		case VerifiedPartial:
			st.VerifiedPartial++
		case VerifiedGap:
			st.VerifiedGap++
		default:
			st.VerifiedUnknown++
		}
	}
	for _, gp := range gaps {
		for _, t := range gp.Techniques {
			techRisk[t.TechniqueID] += gp.score
		}
	}
	ids := make([]string, 0, len(techRisk))
	for id := range techRisk {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var bestVal float64
	for _, id := range ids {
		if techRisk[id] > bestVal {
			bestVal, st.HighestRiskTechnique = techRisk[id], id
		}
	}
	if len(gaps) > 0 {
		e := gaps[0].Edge
		st.HighestRiskEdge = &e
	}
	return st
}

func summarize(paths []AnnotatedPath, stats Statistics) string {
	if stats.EdgesTotal == 0 {
		return "No dangerous attack paths were found to correlate against detection coverage."
	}
	uncovered := stats.VerifiedGap + stats.VerifiedUnknown + stats.VerifiedPartial
	return fmt.Sprintf("%d of %d correlated edges have no fully verified detection across %d attack path(s).",
		uncovered, stats.EdgesTotal, len(paths))
}
