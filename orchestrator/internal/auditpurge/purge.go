// Package auditpurge deletes audit-log rows older than the configured maximum. It runs under the dedicated purge
// role. Each batch is archived, signed and verified (internal/auditarchive) before its rows are deleted, and a
// failure at any step stops the purge with the rows still in place. The purge is off unless Enabled is set.
package auditpurge

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auditarchive"
)

// MinimumRetentionDays is the shortest period audit rows are kept. It matches internal/auditretention.
const MinimumRetentionDays = 180

// Config controls a purge.
type Config struct {
	Enabled          bool
	MaxRetentionDays int    // rows older than this are purged; raised to MinimumRetentionDays if lower
	BatchSize        int    // rows per archived batch
	MaxBatches       int    // stop after this many batches (0 = no limit); lets a purge be run in steps
	ArchiveDir       string // where sealed batches are written; must exist
}

// Recorder writes a metadata record for each purged batch, such as an audit entry.
type Recorder interface {
	Record(ctx context.Context, detail map[string]any) error
}

// EffectiveCutoff is the time before which rows are eligible for purge. The period is never shorter than the
// minimum, so rows inside the window are never eligible. now is converted to UTC.
func EffectiveCutoff(now time.Time, maxDays int) time.Time {
	days := maxDays
	if days < MinimumRetentionDays {
		days = MinimumRetentionDays
	}
	return now.UTC().AddDate(0, 0, -days)
}

// BatchID is the deterministic name of the batch that holds audit ids first..last below cutoff.
func BatchID(cutoff time.Time, first, last int64) string {
	return fmt.Sprintf("purge-%s-%d-%d", cutoff.UTC().Format("20060102T150405Z"), first, last)
}

// Run purges eligible rows in id order, batch by batch. Each batch is archived and verified before it is deleted.
// If archiving, verifying or deleting fails, Run returns the error, and the batch's rows are not deleted unless
// they were already archived and verified. Run does nothing when purging is disabled.
func Run(ctx context.Context, pool *pgxpool.Pool, cfg Config, priv *rsa.PrivateKey, rec Recorder, now time.Time) (int, error) {
	if !cfg.Enabled {
		return 0, nil
	}
	if priv == nil || rec == nil {
		return 0, errors.New("auditpurge: a signing key and a recorder are required when purging is enabled")
	}
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 500
	}
	now = now.UTC()
	cutoff := EffectiveCutoff(now, cfg.MaxRetentionDays)

	var lastID int64
	purged, batches := 0, 0
	for cfg.MaxBatches == 0 || batches < cfg.MaxBatches {
		rows, err := selectBatch(ctx, pool, cutoff, lastID, batchSize)
		if err != nil {
			return purged, err
		}
		if len(rows) == 0 {
			break
		}
		first, last := rows[0].ID, rows[len(rows)-1].ID
		body, err := auditarchive.EncodeRows(rows)
		if err != nil {
			return purged, err
		}
		m, err := auditarchive.Seal(body, auditarchive.Manifest{
			BatchID: BatchID(cutoff, first, last), CutoffUTC: cutoff, CreatedUTC: now,
		}, priv)
		if err != nil {
			return purged, err
		}
		// Archive and verify before any delete. On failure nothing is deleted from this batch.
		if err := auditarchive.WriteArchive(cfg.ArchiveDir, m, body, &priv.PublicKey); err != nil {
			return purged, fmt.Errorf("archive batch %s: %w", m.BatchID, err)
		}
		n, err := deleteBatch(ctx, pool, cutoff, rows)
		if err != nil {
			return purged, err
		}
		if n != len(rows) {
			return purged, fmt.Errorf("batch %s: deleted %d of %d archived rows", m.BatchID, n, len(rows))
		}
		purged += n
		batches++
		lastID = last
		if err := rec.Record(ctx, map[string]any{
			"cutoff_utc":         cutoff.Format(time.RFC3339),
			"batch_id":           m.BatchID,
			"row_count":          n,
			"first_id":           first,
			"last_id":            last,
			"archive_sha256":     m.SHA256,
			"signature_verified": true,
			"signature_alg":      m.Alg,
		}); err != nil {
			return purged, fmt.Errorf("record batch %s: %w", m.BatchID, err)
		}
	}
	return purged, nil
}

// selectBatch returns the next eligible rows in id order.
func selectBatch(ctx context.Context, pool *pgxpool.Pool, cutoff time.Time, afterID int64, n int) ([]auditarchive.Row, error) {
	rs, err := pool.Query(ctx, `SELECT id, ts, actor_id, action, resource, detail::text, ip, outcome
		FROM audit_logs WHERE ts < $1 AND id > $2 ORDER BY id LIMIT $3`, cutoff, afterID, n)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []auditarchive.Row
	for rs.Next() {
		var r auditarchive.Row
		var detail string
		if err := rs.Scan(&r.ID, &r.Ts, &r.ActorID, &r.Action, &r.Resource, &detail, &r.IP, &r.Outcome); err != nil {
			return nil, err
		}
		r.Detail = []byte(detail)
		out = append(out, r)
	}
	return out, rs.Err()
}

// deleteBatch deletes exactly the archived ids, and only while they are still eligible.
func deleteBatch(ctx context.Context, pool *pgxpool.Pool, cutoff time.Time, rows []auditarchive.Row) (int, error) {
	ids := make([]int64, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	tag, err := pool.Exec(ctx, `DELETE FROM audit_logs WHERE id = ANY($1) AND ts < $2`, ids, cutoff)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
