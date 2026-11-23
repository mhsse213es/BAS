package auditpurge

import (
	"context"
	"crypto/rsa"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// StartDaily runs a purge once at start and then every 24 hours until ctx is cancelled. Errors are logged and the
// next run tries again; a failed batch never deletes rows, so a retry is safe.
func StartDaily(ctx context.Context, pool *pgxpool.Pool, cfg Config, priv *rsa.PrivateKey, rec Recorder) {
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			n, err := Run(ctx, pool, cfg, priv, rec, time.Now())
			if err != nil {
				log.Printf("[auditpurge] purge stopped after %d row(s): %v", n, err)
			} else if n > 0 {
				log.Printf("[auditpurge] purged %d audit row(s) older than %d days, each batch archived and verified", n, cfg.MaxRetentionDays)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// AuditRecorder writes each purged batch as an audit entry through the application pool, so the purge itself is
// on the record.
type AuditRecorder struct{ Pool *pgxpool.Pool }

// Record inserts an audit.purge entry carrying the batch detail.
func (a AuditRecorder) Record(ctx context.Context, detail map[string]any) error {
	_, err := a.Pool.Exec(ctx, `INSERT INTO audit_logs (actor_id, action, resource, detail, ip, outcome)
		VALUES ('system', 'audit.purge', 'audit_logs', $1::jsonb, '', 'ok')`, toJSON(detail))
	return err
}
