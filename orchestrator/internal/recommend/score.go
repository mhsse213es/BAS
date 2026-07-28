package recommend

import (
	"fmt"
	"math"
	"time"

	"github.com/audspect/bas/internal/reporting"
)

// Coverage-age band boundaries. Evaluated top-down in CoverageGap so the
// boundaries are unambiguous (see the spec's Scoring section).
const (
	staleAfter  = 90 * 24 * time.Hour
	recentAfter = 30 * 24 * time.Hour
)

// Composite weights — must sum to 1.0. See the Threat Prioritization spec's
// Recommendation Engine Integration section
// (docs/superpowers/specs/2026-07-28-threat-prioritization-design.md).
const (
	wActor       = 0.25
	wThreat      = 0.35
	wCoverage    = 0.25
	wEnvironment = 0.15
)

func clamp100(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// CoverageGap scores 0-100 on how overdue a technique is for testing: never
// tested is the maximum gap, a test in the last 30 days is no gap at all.
func CoverageGap(lastTested *time.Time, now time.Time) int {
	if lastTested == nil {
		return 100
	}
	age := now.Sub(*lastTested)
	switch {
	case age > staleAfter:
		return 60
	case age > recentAfter:
		return 30
	default:
		return 0
	}
}

// CoverageStateFor is the display label matching CoverageGap's bands.
func CoverageStateFor(lastTested *time.Time, now time.Time) string {
	if lastTested == nil {
		return "never-tested"
	}
	if now.Sub(*lastTested) > staleAfter {
		return "stale"
	}
	return "recent"
}

// EnvironmentRisk scores 0-100 on how relevant a technique is to THIS
// environment: 0 when it maps to no edge in the collected graph (never
// fabricate relevance we have no signal for), 50 when it traverses some real
// edge, 100 when that edge sits on a domain-compromise or crown-jewel path,
// +20 when the edge's target carries a critical/high SP6 criticality tier.
func EnvironmentRisk(inGraph, onCriticalPath, targetsCritical bool) int {
	if !inGraph && !onCriticalPath {
		return 0
	}
	risk := 50
	if onCriticalPath {
		risk = 100
	}
	if targetsCritical {
		risk += 20
	}
	return clamp100(risk)
}

// RecommendationScore is the composite: 0.25×actor + 0.35×threat + 0.25×coverage + 0.15×env.
func RecommendationScore(actorPriority, threatPriority, coverageGap, environmentRisk int) int {
	s := wActor*float64(clamp100(actorPriority)) +
		wThreat*float64(clamp100(threatPriority)) +
		wCoverage*float64(clamp100(coverageGap)) +
		wEnvironment*float64(clamp100(environmentRisk))
	return clamp100(int(math.Round(s)))
}

// buildReasons explains a rank in plain language, strongest signal first.
// Never invents a reason it has no data for.
func buildReasons(t RecommendedTechnique, now time.Time) []string {
	var out []string
	switch t.CoverageState {
	case "never-tested":
		out = append(out, "Never tested on this fleet")
	case "stale":
		if t.LastTestedAt != nil {
			out = append(out, fmt.Sprintf("Last tested %d days ago", int(now.Sub(*t.LastTestedAt).Hours()/24)))
		}
	}
	if t.KEV {
		out = append(out, "Linked to a CISA KEV catalog CVE")
	}
	if t.EPSSPercentile >= 90 {
		out = append(out, fmt.Sprintf("EPSS percentile %.0f — top-decile exploitation likelihood", t.EPSSPercentile))
	} else if t.EPSSPercentile >= 70 {
		out = append(out, fmt.Sprintf("EPSS percentile %.0f", t.EPSSPercentile))
	}
	if t.ThreatActors >= 5 {
		out = append(out, fmt.Sprintf("Attributed to %d ATT&CK groups", t.ThreatActors))
	} else if t.ThreatActors >= 1 {
		out = append(out, fmt.Sprintf("Attributed to %d ATT&CK group(s)", t.ThreatActors))
	}
	switch {
	case t.EnvironmentRisk >= 100:
		out = append(out, "Traverses an edge on a domain-compromise or crown-jewel path in your environment")
	case t.EnvironmentRisk >= 70:
		out = append(out, "Traverses an edge targeting a high-criticality asset in your environment")
	case t.EnvironmentRisk > 0:
		out = append(out, "Traverses a real edge in your collected attack-path graph")
	}
	if t.ActorPriority >= 70 {
		out = append(out, fmt.Sprintf("Used by a %s-priority threat actor", reporting.PriorityTierFor(t.ActorPriority)))
	}
	if t.LastVerdict == "fail" {
		out = append(out, "Previously failed — remediate before re-testing")
	}
	return out
}
