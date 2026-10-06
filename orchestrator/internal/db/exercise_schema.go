package db

import (
	"context"
	"github.com/audspect/bas/internal/db/legacy"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureExerciseSchema creates the exercise engine tables.
// Idempotent — safe to call on every startup.
func EnsureExerciseSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return legacy.EnsureExerciseSchema(ctx, pool)
}
