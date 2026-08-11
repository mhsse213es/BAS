package threatpriority

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type IntelFreshnessFactor struct{}

func (IntelFreshnessFactor) Name() string          { return "Intel Freshness" }
func (IntelFreshnessFactor) Weight(Context) float64 { return flatWeight }
func (IntelFreshnessFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	if tctx.Profile == nil || tctx.Profile.LastSeen == nil {
		return 0, "No intel sighting recorded", false, nil
	}
	age := tctx.Now.Sub(*tctx.Profile.LastSeen)
	days := int(age.Hours() / 24)
	switch {
	case age < 30*24*time.Hour:
		return 100, fmt.Sprintf("Last seen %d days ago", days), true, nil
	case age < 90*24*time.Hour:
		return 60, fmt.Sprintf("Last seen %d days ago", days), true, nil
	default:
		return 20, fmt.Sprintf("Last seen %d days ago", days), true, nil
	}
}

type RelevanceFactor struct{}

func (RelevanceFactor) Name() string          { return "Sector/Region Relevance" }
func (RelevanceFactor) Weight(Context) float64 { return flatWeight }
func (RelevanceFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	if len(tctx.Sectors) == 0 && len(tctx.Regions) == 0 {
		return 0, "No organization sectors/regions configured", false, nil
	}
	if tctx.Profile == nil {
		return 0, "No sector/region data for this actor", false, nil
	}
	// Empty here means "no source ever told us" (every OpenCTI-only actor,
	// for example -- OpenCTI's GraphQL query never fetches sector/region
	// relationships), not "checked and confirmed no overlap". Treating it
	// as a confirmed non-match would let a connector's missing data
	// silently count as real evidence against an actor's relevance.
	if len(tctx.Profile.Sectors) == 0 && len(tctx.Profile.Regions) == 0 {
		return 0, "No sector/region data for this actor", false, nil
	}
	if overlapFold(tctx.Profile.Sectors, tctx.Sectors) {
		return 100, "Matches a configured industry sector", true, nil
	}
	if overlapFold(tctx.Profile.Regions, tctx.Regions) {
		return 100, "Matches a configured region", true, nil
	}
	return 0, "No sector or region overlap", true, nil
}

func overlapFold(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if strings.EqualFold(x, y) {
				return true
			}
		}
	}
	return false
}

type ConfidenceFactor struct{}

func (ConfidenceFactor) Name() string          { return "Intel Confidence" }
func (ConfidenceFactor) Weight(Context) float64 { return flatWeight }
func (ConfidenceFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	if tctx.Profile == nil || tctx.Profile.Confidence == "" {
		return 0, "No confidence rating recorded", false, nil
	}
	switch strings.ToLower(tctx.Profile.Confidence) {
	case "high":
		return 100, "High confidence intel", true, nil
	case "medium":
		return 60, "Medium confidence intel", true, nil
	case "low":
		return 30, "Low confidence intel", true, nil
	default:
		return 0, "Unrecognized confidence value", false, nil
	}
}
