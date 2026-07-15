package exposure

import (
	"context"
	"sort"

	"github.com/audspect/bas/internal/relationships"
)

// Per-CVE severity weights (0-100 total): CVSS dominates, KEV (actively
// exploited) is a large flat bonus even when CVSS is unknown, EPSS
// (exploit-probability) contributes the smallest, most volatile term.
const (
	cveWeightCVSS = 60.0
	cveWeightKEV  = 25.0
	cveWeightEPSS = 15.0
)

// cveSeverity is the per-design-spec per-CVE severity formula.
func cveSeverity(cvss float64, kev bool, epss float64) float64 {
	sev := (cvss/10)*cveWeightCVSS + epss*cveWeightEPSS
	if kev {
		sev += cveWeightKEV
	}
	if sev > 100 {
		sev = 100
	}
	if sev < 0 {
		sev = 0
	}
	return sev
}

// vulnerabilitiesForTechniques returns, per technique ID, the CVEs reached
// via an Active, High/Medium-confidence relationship (the Relationship
// Store's documented scoring convention), enriched with CVSS/KEV/EPSS. One
// batched CVEEnricher call covers every technique passed in — never one
// query per technique. nil rels or nil enricher returns an empty map
// (nil-safe, matches this codebase's optional-subsystem convention).
func vulnerabilitiesForTechniques(ctx context.Context, techniqueIDs []string, rels RelationshipLookup, enricher CVEEnricher) (map[string][]CVEExposure, error) {
	if rels == nil || enricher == nil {
		return map[string][]CVEExposure{}, nil
	}

	type pair struct{ techID, cveID string }
	var pairs []pair
	cveSet := map[string]bool{}
	for _, t := range techniqueIDs {
		relList, err := rels.ForTechnique(ctx, t)
		if err != nil {
			return nil, err
		}
		for _, r := range relList {
			if r.Status != relationships.StatusActive {
				continue
			}
			if r.EffectiveConfidence != relationships.ConfidenceHigh && r.EffectiveConfidence != relationships.ConfidenceMedium {
				continue
			}
			pairs = append(pairs, pair{t, r.CVEID})
			cveSet[r.CVEID] = true
		}
	}
	if len(pairs) == 0 {
		return map[string][]CVEExposure{}, nil
	}

	cveIDs := make([]string, 0, len(cveSet))
	for id := range cveSet {
		cveIDs = append(cveIDs, id)
	}
	sort.Strings(cveIDs)

	meta, err := enricher.Enrich(ctx, cveIDs)
	if err != nil {
		return nil, err
	}

	out := map[string][]CVEExposure{}
	for _, p := range pairs {
		m := meta[p.cveID]
		out[p.techID] = append(out[p.techID], CVEExposure{
			CVEID:       p.cveID,
			CVSS:        m.CVSS,
			KEV:         m.KEV,
			EPSSScore:   m.EPSSScore,
			TechniqueID: p.techID,
			Severity:    cveSeverity(m.CVSS, m.KEV, m.EPSSScore),
		})
	}
	return out, nil
}
