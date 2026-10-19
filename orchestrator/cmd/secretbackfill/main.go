// Command secretbackfill scrubs secret-shaped values from rows stored before the
// write-time fix: scenario_runs.results, scenario_runs.detections_raw, and
// iocs.value. It is a dry run unless -apply is set. It prints counts and row
// IDs only, never the values, so the report cannot leak what it finds.
//
// Run it against a backup. Writes cannot be undone.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/secretbackfill"
)

const batchSize = 200

func main() {
	apply := flag.Bool("apply", false, "write the scrubbed values (default: dry run, no writes)")
	flag.Parse()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("secretbackfill requires DATABASE_URL")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	mode := "DRY RUN (no writes)"
	if *apply {
		mode = "APPLY (writing)"
	}
	fmt.Println("secretbackfill:", mode)

	runsChanged, err := backfillRuns(ctx, pool, *apply)
	if err != nil {
		log.Fatalf("scenario_runs: %v", err)
	}
	iocsChanged, collisions, err := backfillIOCs(ctx, pool, *apply)
	if err != nil {
		log.Fatalf("iocs: %v", err)
	}
	fmt.Printf("scenario_runs rows with secrets: %d\n", len(runsChanged))
	fmt.Printf("iocs rows with secrets: %d (skipped, would duplicate an existing value: %d)\n", iocsChanged, len(collisions))
	if len(collisions) > 0 {
		fmt.Println("collision ioc ids (review by hand; the secret stays until resolved):", collisions)
	}
	if !*apply {
		fmt.Println("dry run complete. Re-run with -apply after taking a backup.")
	}
}

// backfillRuns walks scenario_runs in id order and scrubs results and
// detections_raw. It returns the IDs of rows that needed a change.
func backfillRuns(ctx context.Context, pool *pgxpool.Pool, apply bool) ([]string, error) {
	var changedIDs []string
	after := ""
	for {
		rows, err := pool.Query(ctx,
			`SELECT id, results::text, detections_raw::text FROM scenario_runs
			 WHERE id > $1 ORDER BY id LIMIT $2`, after, batchSize)
		if err != nil {
			return nil, err
		}
		type row struct{ id, results, detections string }
		var batch []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.results, &r.detections); err != nil {
				rows.Close()
				return nil, err
			}
			batch = append(batch, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			return changedIDs, nil
		}
		for _, r := range batch {
			after = r.id
			newResults, resChanged, err := secretbackfill.ScrubResults([]byte(r.results))
			if err != nil {
				return nil, fmt.Errorf("run %s results: %w", r.id, err)
			}
			newDetections, detChanged, err := secretbackfill.ScrubAlerts([]byte(r.detections))
			if err != nil {
				return nil, fmt.Errorf("run %s detections_raw: %w", r.id, err)
			}
			if !resChanged && !detChanged {
				continue
			}
			changedIDs = append(changedIDs, r.id)
			if !apply {
				continue
			}
			if _, err := pool.Exec(ctx,
				`UPDATE scenario_runs SET results = $1::jsonb, detections_raw = $2::jsonb WHERE id = $3`,
				string(newResults), string(newDetections), r.id); err != nil {
				return nil, fmt.Errorf("run %s update: %w", r.id, err)
			}
		}
	}
}

// backfillIOCs scrubs iocs.value. A value that would duplicate an existing
// (type, value) pair is skipped and its id returned, never forced: the unique
// index is a real constraint and a merge is a decision for a person.
func backfillIOCs(ctx context.Context, pool *pgxpool.Pool, apply bool) (int, []string, error) {
	rows, err := pool.Query(ctx, `SELECT id, type, value FROM iocs`)
	if err != nil {
		return 0, nil, err
	}
	type ioc struct{ id, typ, value string }
	var all []ioc
	for rows.Next() {
		var i ioc
		if err := rows.Scan(&i.id, &i.typ, &i.value); err != nil {
			rows.Close()
			return 0, nil, err
		}
		all = append(all, i)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}

	changed := 0
	var collisions []string
	for _, i := range all {
		clean := models.WithholdSecrets(i.value)
		if clean == i.value {
			continue
		}
		changed++
		if !apply {
			continue
		}
		if _, err := pool.Exec(ctx, `UPDATE iocs SET value = $1 WHERE id = $2`, clean, i.id); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				collisions = append(collisions, i.id)
				continue
			}
			return changed, collisions, err
		}
	}
	return changed, collisions, nil
}
