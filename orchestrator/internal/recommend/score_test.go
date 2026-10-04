package recommend

import (
	"testing"
	"time"
)

var scoreNow = time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)

func daysAgo(d int) *time.Time {
	t := scoreNow.AddDate(0, 0, -d)
	return &t
}

func TestCoverageGap_Bands(t *testing.T) {
	cases := []struct {
		name       string
		lastTested *time.Time
		want       int
	}{
		{"never tested", nil, 100},
		{"120 days — stale", daysAgo(120), 60},
		{"91 days — just over the stale line", daysAgo(91), 60},
		{"60 days — mid band", daysAgo(60), 30},
		{"31 days — just over the recent line", daysAgo(31), 30},
		{"10 days — recent", daysAgo(10), 0},
		{"today", daysAgo(0), 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CoverageGap(c.lastTested, scoreNow); got != c.want {
				t.Errorf("CoverageGap(%v) = %d, want %d", c.lastTested, got, c.want)
			}
		})
	}
}

func TestCoverageStateFor_Labels(t *testing.T) {
	cases := []struct {
		lastTested *time.Time
		want       string
	}{
		{nil, "never-tested"},
		{daysAgo(120), "stale"},
		{daysAgo(60), "recent"},
		{daysAgo(1), "recent"},
	}
	for _, c := range cases {
		if got := CoverageStateFor(c.lastTested, scoreNow); got != c.want {
			t.Errorf("CoverageStateFor(%v) = %q, want %q", c.lastTested, got, c.want)
		}
	}
}

func TestEnvironmentRisk_Tiers(t *testing.T) {
	cases := []struct {
		name                                 string
		inGraph, onCriticalPath, targetsCrit bool
		want                                 int
	}{
		{"not in the graph at all", false, false, false, 0},
		{"not in graph — critical target is ignored", false, false, true, 0},
		{"in the graph, off the critical paths", true, false, false, 50},
		{"in the graph, targets a critical asset", true, false, true, 70},
		{"on a critical path", true, true, false, 100},
		{"on a critical path AND targets critical — clamps at 100", true, true, true, 100},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := EnvironmentRisk(c.inGraph, c.onCriticalPath, c.targetsCrit); got != c.want {
				t.Errorf("EnvironmentRisk(inGraph=%v, path=%v, crit=%v) = %d, want %d",
					c.inGraph, c.onCriticalPath, c.targetsCrit, got, c.want)
			}
		})
	}
}

// TestRecommendationScore_Weights pins the 0.25/0.35/0.25/0.15 split (actor/
// threat/coverage/env) from the Threat Prioritization spec.
func TestRecommendationScore_Weights(t *testing.T) {
	cases := []struct {
		name                         string
		actor, threat, coverage, env int
		want                         int
	}{
		{"all zero", 0, 0, 0, 0, 0},
		{"all max", 100, 100, 100, 100, 100},
		{"actor only", 100, 0, 0, 0, 25},
		{"threat only", 0, 100, 0, 0, 35},
		{"coverage only", 0, 0, 100, 0, 25},
		{"environment only", 0, 0, 0, 100, 15},
		{"rounds to nearest", 10, 10, 10, 11, 10},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RecommendationScore(c.actor, c.threat, c.coverage, c.env); got != c.want {
				t.Errorf("RecommendationScore(%d, %d, %d, %d) = %d, want %d",
					c.actor, c.threat, c.coverage, c.env, got, c.want)
			}
		})
	}
}

// TestRecommendationScore_HigherActorPriorityIncreasesScore verifies the new
// ActorPriority term moves the composite: a technique tied to a
// Critical-priority actor must outrank an otherwise-identical technique tied
// to a Low-priority actor.
func TestRecommendationScore_HigherActorPriorityIncreasesScore(t *testing.T) {
	high := RecommendationScore(100, 50, 50, 50)
	low := RecommendationScore(0, 50, 50, 50)
	if high <= low {
		t.Fatalf("high actorPriority score (%d) should exceed low (%d)", high, low)
	}
}

// TestRecommendationScore_RecentFailingDoesNotDominate pins the spec's
// Decision 5: a recently-tested FAILING technique carries ComputePriorityScore's
// +10 fail bonus, but CoverageGap=0 must keep it below a never-tested technique
// with otherwise identical signals. You already know it fails — re-running it
// teaches nothing until it is remediated, and the ITSM revalidation loop
// re-tests on ticket-resolve. It is a remediation item, not a testing gap.
func TestRecommendationScore_RecentFailingDoesNotDominate(t *testing.T) {
	// Same underlying threat signals; the failing one even scores 10 higher on
	// threat priority thanks to the fail bonus. actorPriority held at 0 for
	// both so this test isolates the coverage/threat relationship, unaffected
	// by the new actor term.
	recentFailing := RecommendationScore(0, 60, CoverageGap(daysAgo(5), scoreNow), 50)
	neverTested := RecommendationScore(0, 50, CoverageGap(nil, scoreNow), 50)

	if neverTested <= recentFailing {
		t.Errorf("never-tested (%d) should outrank recently-tested-failing (%d)", neverTested, recentFailing)
	}
}
