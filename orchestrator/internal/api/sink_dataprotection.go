package api

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/rwevidence"
)

// sinkDataProtectionSource backs the DataProtection capability with the DLP
// sink's own token and receipt rows for the step's run and technique. The rule
// that turns those counts into a status lives in rwevidence.SinkDataProtectionStatus.
type sinkDataProtectionSource struct {
	pool *pgxpool.Pool
}

// LookupDataProtection satisfies rwevidence.DataProtectionLookup.
func (s sinkDataProtectionSource) LookupDataProtection(ctx context.Context, key rwevidence.AttemptKey) (string, string, error) {
	if s.pool == nil {
		return "", "", nil
	}
	tokens, data, probe, err := db.SinkEvidenceForStep(ctx, s.pool, key.RunID, key.TechniqueID)
	if err != nil {
		return "", "", err
	}
	status, reason := rwevidence.SinkDataProtectionStatus(tokens, data, probe)
	return status, reason, nil
}
