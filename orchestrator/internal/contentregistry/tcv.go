package contentregistry

import (
	"context"
	"time"

	"github.com/audspect/bas/internal/tcv"
)

// qualifiesForTCVStop reports whether this origin/trust/lifecycle
// combination should stop a TCV clock (spec §10.3-§10.4). This is a
// strict SUBSET of Executable(): passing devBuild=false always excludes
// the dev-only combination (an unsigned VENDOR scenario accepted only
// because signing is disabled locally), which lets a scenario run in dev
// but must never count toward a customer-facing coverage metric
// (acceptance test 32). The two real executable combinations do not
// depend on devBuild, so this cannot exclude them.
func qualifiesForTCVStop(origin Origin, trust Trust, lc Lifecycle) bool {
	return Executable(origin, trust, lc, false)
}

// recordCoverageIfExecutable checks whether versionID, in its CURRENT
// origin/trust/lifecycle state, qualifies as executable coverage and, for
// every threat this version is linked to via content_version_threats,
// records a write-once coverage-first stop (spec §10.3). Idempotent
// (threat_coverage_firsts is write-once) -- safe to call after every state
// change a version goes through, not only the one that actually flips it
// to executable. q is the caller's own transaction when one is open, so
// the coverage write is atomic with the state change that caused it.
func (r *Registry) recordCoverageIfExecutable(ctx context.Context, q tcv.Querier, versionID string, origin Origin, trust Trust, lc Lifecycle) error {
	if !qualifiesForTCVStop(origin, trust, lc) {
		return nil
	}
	rows, err := q.Query(ctx, `SELECT threat_id, relationship_kind FROM content_version_threats WHERE content_version_id = $1`, versionID)
	if err != nil {
		return err
	}
	type link struct{ threatID, kind string }
	var links []link
	for rows.Next() {
		var l link
		if err := rows.Scan(&l.threatID, &l.kind); err != nil {
			rows.Close()
			return err
		}
		links = append(links, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	now := time.Now()
	for _, l := range links {
		if err := tcv.RecordCoverageFirst(ctx, q, l.threatID, tcv.RelationshipKind(l.kind), versionID, now); err != nil {
			return err
		}
	}
	return nil
}
