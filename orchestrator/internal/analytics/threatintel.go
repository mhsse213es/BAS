package analytics

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/threatpriority"
)

// ThreatIntelPosture is the fleet-wide threat-intel posture: the most
// urgent actors to validate against, plus exposure to actively-exploited
// (CISA KEV) vulnerabilities.
type ThreatIntelPosture struct {
	TopActors            []threatpriority.ActorPriority `json:"topActors"`
	KEVExposedTechniques int                             `json:"kevExposedTechniques"`
	TotalKEVCVEs         int                              `json:"totalKevCves"`
}

// ThreatIntelSummary computes the fleet-wide threat-intel posture.
// tpEngine may be nil (threat prioritization not configured) -- TopActors
// comes back empty rather than erroring, matching the "nil when not
// loaded" contract h.threatPriorityEngine already follows elsewhere.
func ThreatIntelSummary(ctx context.Context, pool *pgxpool.Pool, tpEngine *threatpriority.Engine) (ThreatIntelPosture, error) {
	var topActors []threatpriority.ActorPriority
	if tpEngine != nil {
		all, err := tpEngine.ScoreAll(ctx)
		if err != nil {
			return ThreatIntelPosture{}, err
		}
		if len(all) > 5 {
			all = all[:5]
		}
		topActors = all
	}

	var kevTechCount, kevCveCount int
	err := pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT tc.technique_id), COUNT(*)
		FROM technique_cves tc
		JOIN cves c ON c.cve_id = tc.cve_id AND c.source = 'cisa-kev'
		WHERE EXISTS (SELECT 1 FROM art_atomic_tests a WHERE a.technique_id = tc.technique_id)`,
	).Scan(&kevTechCount, &kevCveCount)
	if err != nil {
		return ThreatIntelPosture{}, err
	}

	return ThreatIntelPosture{
		TopActors:            topActors,
		KEVExposedTechniques: kevTechCount,
		TotalKEVCVEs:         kevCveCount,
	}, nil
}
