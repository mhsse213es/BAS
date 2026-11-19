package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrAPIBASBindingNotFound means the target has no stored binding spec.
var ErrAPIBASBindingNotFound = errors.New("apibas binding not found")

// APIBASBinding is the test data a target's scenarios are bound with: identities (credential names only, never values) and the
// objects each identity owns. One spec per target; saving replaces it. Spec is the JSON of binding.Spec.
type APIBASBinding struct {
	TargetID           string
	Spec               []byte
	UpdatedBy          string
	UpdatedAt          time.Time
	ValidatedInventory int // the inventory version the spec bound against when it was saved
}

// SaveAPIBASBinding stores or replaces the target's binding spec. The target row is locked so a concurrent delete cannot orphan it.
func SaveAPIBASBinding(ctx context.Context, pool *pgxpool.Pool, rec APIBASBinding) (APIBASBinding, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return rec, fmt.Errorf("begin binding save: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var locked string
	if err := tx.QueryRow(ctx, `SELECT id FROM apibas_targets WHERE id = $1 FOR UPDATE`, rec.TargetID).Scan(&locked); errors.Is(err, pgx.ErrNoRows) {
		return rec, ErrAPIBASTargetNotFound
	} else if err != nil {
		return rec, fmt.Errorf("lock apibas target: %w", err)
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO apibas_target_bindings (target_id, spec, updated_by, validated_inventory)
		VALUES ($1, $2::jsonb, $3, $4)
		ON CONFLICT (target_id) DO UPDATE
		   SET spec = EXCLUDED.spec, updated_by = EXCLUDED.updated_by, updated_at = NOW(), validated_inventory = EXCLUDED.validated_inventory
		RETURNING updated_at`, rec.TargetID, string(rec.Spec), rec.UpdatedBy, rec.ValidatedInventory).Scan(&rec.UpdatedAt)
	if err != nil {
		return rec, fmt.Errorf("save apibas binding: %w", err)
	}
	return rec, tx.Commit(ctx)
}

// GetAPIBASBinding returns the target's stored binding spec.
func GetAPIBASBinding(ctx context.Context, pool *pgxpool.Pool, targetID string) (APIBASBinding, error) {
	var b APIBASBinding
	var spec string
	err := pool.QueryRow(ctx, `SELECT target_id, spec::text, updated_by, updated_at, validated_inventory FROM apibas_target_bindings WHERE target_id = $1`, targetID).
		Scan(&b.TargetID, &spec, &b.UpdatedBy, &b.UpdatedAt, &b.ValidatedInventory)
	if errors.Is(err, pgx.ErrNoRows) {
		return b, ErrAPIBASBindingNotFound
	}
	if err != nil {
		return b, fmt.Errorf("read apibas binding: %w", err)
	}
	b.Spec = []byte(spec)
	return b, nil
}

// DeleteAPIBASBinding removes the target's binding spec and reports whether one existed.
func DeleteAPIBASBinding(ctx context.Context, pool *pgxpool.Pool, targetID string) (bool, error) {
	tag, err := pool.Exec(ctx, `DELETE FROM apibas_target_bindings WHERE target_id = $1`, targetID)
	if err != nil {
		return false, fmt.Errorf("delete apibas binding: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}
