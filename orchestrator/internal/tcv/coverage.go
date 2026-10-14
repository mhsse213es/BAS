package tcv

import (
	"context"
	"fmt"
	"time"
)

// RecordCoverageFirst writes the write-once moment a content version
// linked to threatID by kind first satisfies the execution gate (spec
// §10.3). ON CONFLICT DO NOTHING means a later call -- from a different
// version, or from the same version transitioning again -- never moves
// an already-recorded stop (acceptance tests 28, 31, 32).
func RecordCoverageFirst(ctx context.Context, q Querier, threatID string, kind RelationshipKind, contentVersionID string, firstExecutableAt time.Time) error {
	if _, err := q.Exec(ctx, `INSERT INTO threat_coverage_firsts (threat_id, relationship_kind, content_version_id, first_executable_at)
		VALUES ($1, $2, $3, $4) ON CONFLICT (threat_id, relationship_kind) DO NOTHING`,
		threatID, kind, contentVersionID, firstExecutableAt); err != nil {
		return fmt.Errorf("tcv: record coverage first for %s/%s: %w", threatID, kind, err)
	}
	return nil
}
