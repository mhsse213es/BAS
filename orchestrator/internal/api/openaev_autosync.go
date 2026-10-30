package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/openaev"
)

// errOpenAEVNotEnabled means the connector is not configured or is switched off.
// The background loop treats it as "nothing to do", not as a failure.
var errOpenAEVNotEnabled = errors.New("openaev is not configured/enabled")

// runOpenAEVSync syncs OpenAEV scenarios once and records the outcome on openaev_config.
// The manual endpoint and the background loop both call it, so both record the same way.
func runOpenAEVSync(ctx context.Context, pool *pgxpool.Pool) (*openaev.SyncResult, error) {
	var baseURL, token string
	var enabled bool
	if err := pool.QueryRow(ctx,
		`SELECT base_url, bearer_token, enabled FROM openaev_config WHERE id = 1`).
		Scan(&baseURL, &token, &enabled); err != nil || !enabled {
		return nil, errOpenAEVNotEnabled
	}

	importer := openaev.NewImporter(openaev.NewSQLStore(pool))
	provider := openaev.NewCompositeProvider(
		openaev.NewRESTProvider(baseURL, token),
		openaev.NewExerciseRESTProvider(baseURL, token),
	)
	result, syncErr := importer.SyncAll(ctx, provider)

	status, lastErr := "ok", ""
	created, updated, skipped, errored := 0, 0, 0, 0
	if syncErr != nil {
		status, lastErr = "error", syncErr.Error()
	} else if result != nil {
		created, updated, skipped, errored = result.Created, result.Updated, result.Skipped, result.Errored
	}
	_, _ = pool.Exec(ctx,
		`UPDATE openaev_config SET last_sync_at = NOW(), last_sync_status = $1, last_error = $2,
		   last_sync_created = $3, last_sync_updated = $4, last_sync_skipped = $5, last_sync_errored = $6
		 WHERE id = 1`,
		status, lastErr, created, updated, skipped, errored)
	return result, syncErr
}

// openAEVSyncDue reports whether an automatic sync should run now. It runs when the
// connector is enabled and either has never synced or its last sync is older than the
// configured poll_interval_hours. The admin's interval is the source of truth.
func openAEVSyncDue(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	var enabled bool
	var hours int
	var last *time.Time
	err := pool.QueryRow(ctx,
		`SELECT enabled, poll_interval_hours, last_sync_at FROM openaev_config WHERE id = 1`).
		Scan(&enabled, &hours, &last)
	if err != nil || !enabled {
		return false, nil
	}
	if last == nil {
		return true, nil
	}
	return time.Since(*last) >= time.Duration(hours)*time.Hour, nil
}

// StartOpenAEVAutoSync checks the OpenAEV connector once an hour and syncs when it is due
// (see openAEVSyncDue), so new scenarios appear without a manual sync. A disabled connector
// is skipped quietly. A failed sync is recorded on the config row and logged, and the loop
// keeps going. It stops when ctx is cancelled.
func StartOpenAEVAutoSync(ctx context.Context, pool *pgxpool.Pool, check time.Duration) {
	syncOnce := func() {
		due, err := openAEVSyncDue(ctx, pool)
		if err != nil || !due {
			return
		}
		result, err := runOpenAEVSync(ctx, pool)
		if errors.Is(err, errOpenAEVNotEnabled) {
			return
		}
		detail := fmt.Sprintf("created=%d errored=%d", resultCount(result, true), resultCount(result, false))
		outcome := "ok"
		if err != nil {
			outcome = "error"
			log.Printf("[!] openaev auto-sync: %v", err)
		}
		_, _ = pool.Exec(ctx,
			`INSERT INTO audit_logs (actor_id, action, resource, detail, ip, outcome)
			 VALUES ('', 'openaev.sync.auto', '', $1, '', $2)`,
			`{"summary":"`+detail+`"}`, outcome)
	}
	syncOnce()
	t := time.NewTicker(check)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			syncOnce()
		}
	}
}

// resultCount reads one count from a sync result, tolerating a nil result on error.
func resultCount(r *openaev.SyncResult, created bool) int {
	if r == nil {
		return 0
	}
	if created {
		return r.Created
	}
	return r.Errored
}
