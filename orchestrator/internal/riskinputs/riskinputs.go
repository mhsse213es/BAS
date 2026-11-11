// Package riskinputs stores the customer-entered inputs for the estimated annual loss figure
// (see internal/riskquant). Every write records the value before and after, the actor and the time,
// in an append-only history, so any past value can be reconstructed. Nothing here assumes a currency
// or a default value: an unset currency or an absent input stays absent.
package riskinputs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/audspect/bas/internal/riskquant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when clearing an input that is not stored.
var ErrNotFound = errors.New("risk input not found")

var currencyRE = regexp.MustCompile(`^[A-Z]{3}$`)

// Input is the stored input for one ATT&CK technique.
type Input struct {
	TechniqueID string
	Label       string
	Frequency   riskquant.Range
	Magnitude   riskquant.Range
	UpdatedBy   string
	UpdatedAt   time.Time
	Version     int64
}

// Snapshot is the value part of an Input, as stored in the history.
type Snapshot struct {
	Label     string          `json:"label"`
	Frequency riskquant.Range `json:"frequency"`
	Magnitude riskquant.Range `json:"magnitude"`
}

// HistoryEntry is one recorded change. Previous is nil for the first set; Current is nil for a clear.
type HistoryEntry struct {
	TechniqueID string
	Action      string
	Previous    *Snapshot
	Current     *Snapshot
	Actor       string
	ChangedAt   time.Time
}

func validate(in Input, actor string) error {
	if strings.TrimSpace(in.TechniqueID) == "" {
		return errors.New("riskinputs: technique ID is required")
	}
	if strings.TrimSpace(actor) == "" {
		return errors.New("riskinputs: the actor is required")
	}
	if err := riskquant.ValidateRange(&in.Frequency); err != nil {
		return fmt.Errorf("riskinputs: frequency: %w", err)
	}
	if err := riskquant.ValidateRange(&in.Magnitude); err != nil {
		return fmt.Errorf("riskinputs: magnitude: %w", err)
	}
	return nil
}

// Currency returns the deployment currency, or "" when it has not been set.
func Currency(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	var c string
	err := pool.QueryRow(ctx, `SELECT currency FROM risk_settings WHERE id = 1`).Scan(&c)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return c, err
}

// SetCurrency stores the deployment currency. It returns the previous value, which may be "".
func SetCurrency(ctx context.Context, pool *pgxpool.Pool, code, actor string) (string, error) {
	if !currencyRE.MatchString(code) {
		return "", fmt.Errorf("riskinputs: currency must be a three-letter upper-case code, got %q", code)
	}
	if strings.TrimSpace(actor) == "" {
		return "", errors.New("riskinputs: the actor is required")
	}
	prev, err := Currency(ctx, pool)
	if err != nil {
		return "", err
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO risk_settings (id, currency, updated_by, updated_at) VALUES (1, $1, $2, NOW())
		ON CONFLICT (id) DO UPDATE SET currency = $1, updated_by = $2, updated_at = NOW()`, code, actor)
	return prev, err
}

// List returns every stored input, ordered by technique.
func List(ctx context.Context, pool *pgxpool.Pool) ([]Input, error) {
	rows, err := pool.Query(ctx, `
		SELECT technique_id, label, freq_low, freq_likely, freq_high, mag_low, mag_likely, mag_high,
		       updated_by, updated_at, version
		  FROM risk_exposure_input ORDER BY technique_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Input
	for rows.Next() {
		var in Input
		if err := rows.Scan(&in.TechniqueID, &in.Label,
			&in.Frequency.Low, &in.Frequency.Likely, &in.Frequency.High,
			&in.Magnitude.Low, &in.Magnitude.Likely, &in.Magnitude.High,
			&in.UpdatedBy, &in.UpdatedAt, &in.Version); err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// Put sets the input for a technique, validating it first. The current row and the history entry are
// written in one transaction, so a failure leaves neither changed.
func Put(ctx context.Context, pool *pgxpool.Pool, in Input, actor string) (Input, error) {
	if err := validate(in, actor); err != nil {
		return Input{}, err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return Input{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	prev, err := lockedSnapshot(ctx, tx, in.TechniqueID)
	if err != nil {
		return Input{}, err
	}
	cur := Snapshot{Label: in.Label, Frequency: in.Frequency, Magnitude: in.Magnitude}
	if err := tx.QueryRow(ctx, `
		INSERT INTO risk_exposure_input
		  (technique_id, label, freq_low, freq_likely, freq_high, mag_low, mag_likely, mag_high, updated_by, updated_at, version)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW(),1)
		ON CONFLICT (technique_id) DO UPDATE SET
		  label=$2, freq_low=$3, freq_likely=$4, freq_high=$5, mag_low=$6, mag_likely=$7, mag_high=$8,
		  updated_by=$9, updated_at=NOW(), version=risk_exposure_input.version+1
		RETURNING updated_at, version`,
		in.TechniqueID, in.Label,
		in.Frequency.Low, in.Frequency.Likely, in.Frequency.High,
		in.Magnitude.Low, in.Magnitude.Likely, in.Magnitude.High, actor,
	).Scan(&in.UpdatedAt, &in.Version); err != nil {
		return Input{}, err
	}
	if err := insertHistory(ctx, tx, in.TechniqueID, "set", prev, &cur, actor); err != nil {
		return Input{}, err
	}
	in.UpdatedBy = actor
	if err := tx.Commit(ctx); err != nil {
		return Input{}, err
	}
	return in, nil
}

// Clear removes the input for a technique and records the value that was removed.
func Clear(ctx context.Context, pool *pgxpool.Pool, techniqueID, actor string) error {
	if strings.TrimSpace(techniqueID) == "" || strings.TrimSpace(actor) == "" {
		return errors.New("riskinputs: technique ID and actor are required")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	prev, err := lockedSnapshot(ctx, tx, techniqueID)
	if err != nil {
		return err
	}
	if prev == nil {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM risk_exposure_input WHERE technique_id = $1`, techniqueID); err != nil {
		return err
	}
	if err := insertHistory(ctx, tx, techniqueID, "clear", prev, nil, actor); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// History returns every recorded change for a technique, oldest first.
func History(ctx context.Context, pool *pgxpool.Pool, techniqueID string) ([]HistoryEntry, error) {
	rows, err := pool.Query(ctx, `
		SELECT technique_id, action, previous, current, actor, changed_at
		  FROM risk_exposure_input_history WHERE technique_id = $1 ORDER BY id`, techniqueID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HistoryEntry
	for rows.Next() {
		var h HistoryEntry
		var prev, cur []byte
		if err := rows.Scan(&h.TechniqueID, &h.Action, &prev, &cur, &h.Actor, &h.ChangedAt); err != nil {
			return nil, err
		}
		if h.Previous, err = decodeSnapshot(prev); err != nil {
			return nil, err
		}
		if h.Current, err = decodeSnapshot(cur); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// lockedSnapshot reads the current value under a row lock, so two concurrent writes to one technique
// serialise. It returns nil when no input is stored.
func lockedSnapshot(ctx context.Context, tx pgx.Tx, techniqueID string) (*Snapshot, error) {
	var s Snapshot
	err := tx.QueryRow(ctx, `
		SELECT label, freq_low, freq_likely, freq_high, mag_low, mag_likely, mag_high
		  FROM risk_exposure_input WHERE technique_id = $1 FOR UPDATE`, techniqueID).Scan(
		&s.Label,
		&s.Frequency.Low, &s.Frequency.Likely, &s.Frequency.High,
		&s.Magnitude.Low, &s.Magnitude.Likely, &s.Magnitude.High)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func insertHistory(ctx context.Context, tx pgx.Tx, techniqueID, action string, prev, cur *Snapshot, actor string) error {
	p, err := encodeSnapshot(prev)
	if err != nil {
		return err
	}
	c, err := encodeSnapshot(cur)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO risk_exposure_input_history (technique_id, action, previous, current, actor)
		VALUES ($1, $2, $3, $4, $5)`, techniqueID, action, p, c, actor)
	return err
}

func encodeSnapshot(s *Snapshot) ([]byte, error) {
	if s == nil {
		return nil, nil
	}
	return json.Marshal(s)
}

func decodeSnapshot(b []byte) (*Snapshot, error) {
	if len(b) == 0 || string(b) == "null" {
		return nil, nil
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
