package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ADControlDecision mirrors adefficacy.ControlDecision's fields as plain
// strings/bool so this package never imports adefficacy -- importing it
// would create db -> adefficacy -> adcontrolval -> admatrix -> detectverify
// -> verification -> (verification's tests) -> testutil -> db, an import
// cycle. The caller (internal/api, which already imports adefficacy)
// converts at the boundary.
type ADControlDecision struct {
	DRSUAPIResult string // "access_denied" / "succeeded" / "indeterminate"
	Corroboration string
	Correlated    bool
	Detail        string
}

// WriteADControlVerification persists one real control-decision observation
// for an AD primitive (e.g. "dcsync"), upserted on (run_id, action) -- a
// retry of the same run/action overwrites its own prior row rather than
// duplicating it.
func WriteADControlVerification(ctx context.Context, pool *pgxpool.Pool, runID, primitiveID, techniqueID, action string, d ADControlDecision) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO ad_control_verifications
			(run_id, primitive_id, technique_id, action, drsuapi_result, corroboration, correlated, detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (run_id, action) DO UPDATE SET
			primitive_id   = EXCLUDED.primitive_id,
			technique_id   = EXCLUDED.technique_id,
			drsuapi_result = EXCLUDED.drsuapi_result,
			corroboration  = EXCLUDED.corroboration,
			correlated     = EXCLUDED.correlated,
			detail         = EXCLUDED.detail,
			observed_at    = NOW()
	`, runID, primitiveID, techniqueID, action, d.DRSUAPIResult, d.Corroboration, d.Correlated, d.Detail)
	if err != nil {
		return fmt.Errorf("ad_control_verifications: write run=%s action=%s: %w", runID, action, err)
	}
	return nil
}

// LatestADControlVerification returns the most recently observed
// ControlDecision for primitiveID across any run, or found=false if no
// verification has ever been written for it.
func LatestADControlVerification(ctx context.Context, pool *pgxpool.Pool, primitiveID string) (ADControlDecision, bool, error) {
	var d ADControlDecision
	err := pool.QueryRow(ctx, `
		SELECT drsuapi_result, corroboration, correlated, detail
		FROM ad_control_verifications
		WHERE primitive_id = $1
		ORDER BY observed_at DESC
		LIMIT 1
	`, primitiveID).Scan(&d.DRSUAPIResult, &d.Corroboration, &d.Correlated, &d.Detail)
	if err == pgx.ErrNoRows {
		return ADControlDecision{}, false, nil
	}
	if err != nil {
		return ADControlDecision{}, false, fmt.Errorf("ad_control_verifications: read primitive=%s: %w", primitiveID, err)
	}
	return d, true, nil
}
