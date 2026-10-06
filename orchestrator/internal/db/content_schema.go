package db

import (
	"context"
	"github.com/audspect/bas/internal/db/legacy"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureContentSchema creates the ART content + technique knowledge-graph tables.
//
// It is kept separate from EnsureSchema so the security-content model stays
// self-contained and easy to reason about. The design follows three rules:
//
//   - Payload binaries live on disk; the DB stores metadata + storage_path only.
//   - Atomics are split into a raw import layer (art_atomic_raw, original YAML)
//     and a runtime layer (art_atomic_tests, parsed execution-ready rows) so the
//     server never re-parses YAML at dispatch time.
//   - Techniques are first-class objects; CVE/OWASP/scenario link tables are
//     created now (even if unpopulated) to avoid a painful migration once the
//     platform grows a knowledge graph.
//
// Idempotent — safe to call on every startup.
func EnsureContentSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return legacy.EnsureContentSchema(ctx, pool)
}
