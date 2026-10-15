package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/regobligation"
)

// EnsureRegulatoryObligationSchema creates the regulatory_obligations
// table. created_at is DB-assigned (DEFAULT NOW()), never passed by the
// caller -- same omission zoneisolation.InsertZoneIsolationImport makes
// for imported_at.
func EnsureRegulatoryObligationSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS regulatory_obligations (
			id               text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			created_by       text,
			created_at       timestamptz NOT NULL DEFAULT NOW(),
			obligation_data  jsonb       NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("regulatory_obligations: ensure schema: %w", err)
	}
	return nil
}

// regulatoryObligationData is the shape persisted in the
// obligation_data jsonb column -- everything except id/created_by/
// created_at, which live in their own columns.
type regulatoryObligationData struct {
	Jurisdiction    string                         `json:"jurisdiction"`
	Regulator       string                         `json:"regulator"`
	Sector          string                         `json:"sector,omitempty"`
	EntityType      string                         `json:"entityType,omitempty"`
	Title           string                         `json:"title"`
	Description     string                         `json:"description,omitempty"`
	ObligationType  regobligation.ObligationType   `json:"obligationType"`
	SourceReference string                         `json:"sourceReference"`
	EffectiveDate   time.Time                      `json:"effectiveDate"`
	Version         string                         `json:"version"`
	ControlMappings []regobligation.ControlMapping `json:"controlMappings"`
}

// InsertRegulatoryObligation writes a new regulatory_obligations row.
// The caller supplies ob.ID already generated.
func InsertRegulatoryObligation(ctx context.Context, pool *pgxpool.Pool, ob *regobligation.Obligation) error {
	data, err := json.Marshal(regulatoryObligationData{
		Jurisdiction: ob.Jurisdiction, Regulator: ob.Regulator, Sector: ob.Sector, EntityType: ob.EntityType,
		Title: ob.Title, Description: ob.Description, ObligationType: ob.ObligationType,
		SourceReference: ob.SourceReference, EffectiveDate: ob.EffectiveDate, Version: ob.Version,
		ControlMappings: ob.ControlMappings,
	})
	if err != nil {
		return fmt.Errorf("regulatory_obligations: marshal obligation data for %s: %w", ob.ID, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO regulatory_obligations (id, created_by, obligation_data)
		 VALUES ($1,$2,$3)`,
		ob.ID, nullableString(ob.CreatedBy), data)
	if err != nil {
		return fmt.Errorf("regulatory_obligations: insert %s: %w", ob.ID, err)
	}
	return nil
}

func scanRegulatoryObligation(row pgx.Row) (*regobligation.Obligation, error) {
	ob := &regobligation.Obligation{}
	var createdBy *string
	var data []byte
	if err := row.Scan(&ob.ID, &createdBy, &ob.CreatedAt, &data); err != nil {
		return nil, err
	}
	if createdBy != nil {
		ob.CreatedBy = *createdBy
	}
	var rd regulatoryObligationData
	if err := json.Unmarshal(data, &rd); err != nil {
		return nil, fmt.Errorf("regulatory_obligations: unmarshal obligation data for %s: %w", ob.ID, err)
	}
	ob.Jurisdiction, ob.Regulator, ob.Sector, ob.EntityType = rd.Jurisdiction, rd.Regulator, rd.Sector, rd.EntityType
	ob.Title, ob.Description, ob.ObligationType = rd.Title, rd.Description, rd.ObligationType
	ob.SourceReference, ob.EffectiveDate, ob.Version = rd.SourceReference, rd.EffectiveDate, rd.Version
	ob.ControlMappings = rd.ControlMappings
	return ob, nil
}

// GetRegulatoryObligation returns one obligation by id. A missing id
// returns an error satisfying errors.Is(err, pgx.ErrNoRows).
func GetRegulatoryObligation(ctx context.Context, pool *pgxpool.Pool, id string) (*regobligation.Obligation, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, created_by, created_at, obligation_data FROM regulatory_obligations WHERE id = $1`, id)
	ob, err := scanRegulatoryObligation(row)
	if err != nil {
		return nil, fmt.Errorf("regulatory_obligations: get %s: %w", id, err)
	}
	return ob, nil
}

// ListRegulatoryObligations returns up to limit rows, newest first.
func ListRegulatoryObligations(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*regobligation.Obligation, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, created_by, created_at, obligation_data FROM regulatory_obligations ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("regulatory_obligations: list: %w", err)
	}
	defer rows.Close()
	var out []*regobligation.Obligation
	for rows.Next() {
		ob, err := scanRegulatoryObligation(rows)
		if err != nil {
			return nil, fmt.Errorf("regulatory_obligations: list scan: %w", err)
		}
		out = append(out, ob)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("regulatory_obligations: list rows: %w", err)
	}
	return out, nil
}
