// Command fraudverdictbackfill folds stored fraud-control verdicts into the
// result of scenario_runs rows written before the fix. Those rows still carry
// the endpoint verdict in results[].result, so dashboards, PDF, CSV and run
// lists show a PASS for a step whose fraud control FAILed.
//
// It is a dry run unless -apply is set. It prints counts and run IDs only. For
// each changed run with a stored score it recomputes that score, using the same
// previous-run trend lookup as the live scoring path. Rows without a stored
// score are left for the live path to score when they next finish.
//
// Run it against a backup. Writes cannot be undone. Safe to re-run: rows that
// are already folded are skipped.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
)

const batchSize = 200

func main() {
	apply := flag.Bool("apply", false, "write the folded results and recomputed scores (default: dry run, no writes)")
	flag.Parse()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("fraudverdictbackfill requires DATABASE_URL")
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
	fmt.Println("fraudverdictbackfill:", mode)

	changed, scored, err := backfill(ctx, pool, *apply)
	if err != nil {
		log.Fatalf("scenario_runs: %v", err)
	}
	fmt.Printf("scenario_runs rows with fraud verdicts to fold: %d\n", len(changed))
	fmt.Printf("of those, stored scores recomputed: %d\n", scored)
	if !*apply {
		fmt.Println("dry run complete. Re-run with -apply after taking a backup.")
	}
}

type runRow struct {
	id, scenarioID, agentID string
	results                 []byte
	score                   []byte
}

// backfill walks scenario_runs in id order. It returns the IDs of rows that
// needed a change and how many of those had a score recomputed.
func backfill(ctx context.Context, pool *pgxpool.Pool, apply bool) ([]string, int, error) {
	var changedIDs []string
	scored := 0
	after := ""
	for {
		rows, err := pool.Query(ctx,
			`SELECT id, scenario_id, agent_id, results, score FROM scenario_runs
			 WHERE id > $1 AND results::text LIKE '%fraudControl%'
			 ORDER BY id LIMIT $2`, after, batchSize)
		if err != nil {
			return nil, scored, err
		}
		var batch []runRow
		for rows.Next() {
			var r runRow
			if err := rows.Scan(&r.id, &r.scenarioID, &r.agentID, &r.results, &r.score); err != nil {
				rows.Close()
				return nil, scored, err
			}
			batch = append(batch, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, scored, err
		}
		if len(batch) == 0 {
			return changedIDs, scored, nil
		}
		for _, r := range batch {
			after = r.id
			var results []models.SimulationResult
			if err := json.Unmarshal(r.results, &results); err != nil {
				return nil, scored, fmt.Errorf("run %s results: %w", r.id, err)
			}
			folded, changed := models.BackfillFraudVerdicts(results)
			if !changed {
				continue
			}
			changedIDs = append(changedIDs, r.id)

			var newScore []byte
			if len(r.score) > 0 && string(r.score) != "null" {
				prev, err := previousScore(ctx, pool, r.id, r.scenarioID, r.agentID)
				if err != nil {
					return nil, scored, fmt.Errorf("run %s previous score: %w", r.id, err)
				}
				s := models.ComputeScore(folded, prev)
				newScore, err = json.Marshal(s)
				if err != nil {
					return nil, scored, fmt.Errorf("run %s score: %w", r.id, err)
				}
				scored++
			}
			if !apply {
				continue
			}
			newResults, err := json.Marshal(folded)
			if err != nil {
				return nil, scored, fmt.Errorf("run %s marshal: %w", r.id, err)
			}
			if newScore != nil {
				_, err = pool.Exec(ctx,
					`UPDATE scenario_runs SET results = $1::jsonb, score = $2::jsonb WHERE id = $3`,
					string(newResults), string(newScore), r.id)
			} else {
				_, err = pool.Exec(ctx,
					`UPDATE scenario_runs SET results = $1::jsonb WHERE id = $2`,
					string(newResults), r.id)
			}
			if err != nil {
				return nil, scored, fmt.Errorf("run %s update: %w", r.id, err)
			}
		}
	}
}

// previousScore mirrors the live scoring path: the most recent completed score
// for the same scenario and agent, excluding this run.
func previousScore(ctx context.Context, pool *pgxpool.Pool, runID, scenarioID, agentID string) (*models.Score, error) {
	var raw []byte
	err := pool.QueryRow(ctx,
		`SELECT score FROM scenario_runs
		 WHERE scenario_id = $1 AND agent_id = $2 AND id != $3
		   AND status IN ('completed','partial') AND score IS NOT NULL
		 ORDER BY completed_at DESC LIMIT 1`,
		scenarioID, agentID, runID,
	).Scan(&raw)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ps models.Score
	if json.Unmarshal(raw, &ps) != nil {
		return nil, nil
	}
	return &ps, nil
}
