package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// APIBASRun is one stored run of one build. Report is the JSON report apibas-runner prints. It must be valid
// JSON. Outcome fields are copied out so they can be queried without parsing the report.
type APIBASRun struct {
	ID             string
	RunTag         string
	ScenarioID     string
	Build          string // "vulnerable" or "fixed"
	Protocol       string
	Result         string // PASS, FAIL, ERROR or SKIPPED
	Exploitability string
	Control        string
	Detection      string
	Reason         string
	Report         []byte
	StartedAt      time.Time
	CreatedAt      time.Time
}

// ErrAPIBASRunInvalid means a run failed validation before it reached the database.
var ErrAPIBASRunInvalid = errors.New("apibas run invalid")

// ErrAPIBASRunDuplicate means a run with the same tag and build is already stored.
var ErrAPIBASRunDuplicate = errors.New("apibas run already stored for this tag and build")

func (r APIBASRun) validate() error {
	switch {
	case r.RunTag == "":
		return fmt.Errorf("%w: run tag is empty", ErrAPIBASRunInvalid)
	case r.ScenarioID == "":
		return fmt.Errorf("%w: scenario id is empty", ErrAPIBASRunInvalid)
	case r.Build != "vulnerable" && r.Build != "fixed":
		return fmt.Errorf("%w: build %q is not vulnerable or fixed", ErrAPIBASRunInvalid, r.Build)
	case r.Result != "PASS" && r.Result != "FAIL" && r.Result != "ERROR" && r.Result != "SKIPPED":
		return fmt.Errorf("%w: result %q is not a grade", ErrAPIBASRunInvalid, r.Result)
	case !json.Valid(r.Report):
		return fmt.Errorf("%w: report is not valid JSON", ErrAPIBASRunInvalid)
	}
	return nil
}

// SaveAPIBASRun stores one run and returns its id. A second save of the same tag and build is refused, so a
// rerun cannot silently replace the first record.
func SaveAPIBASRun(ctx context.Context, pool *pgxpool.Pool, r APIBASRun) (string, error) {
	if err := r.validate(); err != nil {
		return "", err
	}
	protocol := r.Protocol
	if protocol == "" {
		protocol = "http"
	}
	var id string
	err := pool.QueryRow(ctx, `
		INSERT INTO apibas_runs
			(run_tag, scenario_id, build, protocol, result, exploitability, control, detection, reason, report)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
		RETURNING id`,
		r.RunTag, r.ScenarioID, r.Build, protocol, r.Result, r.Exploitability, r.Control, r.Detection, r.Reason,
		string(r.Report)).Scan(&id)
	if err != nil {
		var pgErr interface{ SQLState() string }
		if errors.As(err, &pgErr) && pgErr.SQLState() == "23505" {
			return "", ErrAPIBASRunDuplicate
		}
		return "", fmt.Errorf("save apibas run: %w", err)
	}
	return id, nil
}

// ErrAPIBASRunNotFound means no stored run has the id.
var ErrAPIBASRunNotFound = errors.New("apibas run not found")

// GetAPIBASRun returns one stored run, including its report.
func GetAPIBASRun(ctx context.Context, pool *pgxpool.Pool, id string) (APIBASRun, error) {
	var r APIBASRun
	err := pool.QueryRow(ctx, `
		SELECT id, run_tag, scenario_id, build, protocol, result, exploitability, control, detection, reason,
		       report::text, started_at, created_at
		FROM apibas_runs WHERE id = $1`, id).Scan(&r.ID, &r.RunTag, &r.ScenarioID, &r.Build, &r.Protocol,
		&r.Result, &r.Exploitability, &r.Control, &r.Detection, &r.Reason, &r.Report, &r.StartedAt, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIBASRun{}, ErrAPIBASRunNotFound
	}
	if err != nil {
		return APIBASRun{}, fmt.Errorf("get apibas run: %w", err)
	}
	return r, nil
}

// ListAPIBASRuns returns stored runs newest first, without the report body. An empty scenarioID lists every
// scenario.
func ListAPIBASRuns(ctx context.Context, pool *pgxpool.Pool, scenarioID string, limit int) ([]APIBASRun, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := pool.Query(ctx, `
		SELECT id, run_tag, scenario_id, build, protocol, result, exploitability, control, detection, reason,
		       started_at, created_at
		FROM apibas_runs WHERE ($1 = '' OR scenario_id = $1)
		ORDER BY created_at DESC, id DESC LIMIT $2`, scenarioID, limit)
	if err != nil {
		return nil, fmt.Errorf("list apibas runs: %w", err)
	}
	defer rows.Close()
	var out []APIBASRun
	for rows.Next() {
		var r APIBASRun
		if err := rows.Scan(&r.ID, &r.RunTag, &r.ScenarioID, &r.Build, &r.Protocol, &r.Result, &r.Exploitability,
			&r.Control, &r.Detection, &r.Reason, &r.StartedAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
