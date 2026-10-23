package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/dbsim"
)

// EnsureDBSimTargetSchema creates dbsim_targets and dbsim_settings (idempotent).
// The DDL lives in internal/dbsim so its shape is testable without Docker.
func EnsureDBSimTargetSchema(ctx context.Context, pool *pgxpool.Pool) error {
	for _, s := range dbsim.TargetsSchemaSQL {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("dbsim_targets: ensure schema: %w", err)
		}
	}
	for _, s := range dbsim.SettingsSchemaSQL {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("dbsim_settings: ensure schema: %w", err)
		}
	}
	return nil
}

// DBSimTargetStore is the Postgres-backed target registry (it satisfies
// dbadmin.TargetStore structurally). It stores credential REFERENCES only.
type DBSimTargetStore struct{ Pool *pgxpool.Pool }

const dbsimTargetCols = `id, display_name, engine, host, port, db_server_host, database_name, tls_mode,
	credential_ref, expected_identity, mode, lab_confirmed, created_by, created_at,
	identity_check_passed, identity_check_at, identity_check_by, identity_check_reasons`

func scanDBSimTarget(row pgx.Row) (dbsim.TargetRecord, error) {
	var (
		r       dbsim.TargetRecord
		mode    string
		at      *time.Time
		reasons []byte
		passed  bool
	)
	if err := row.Scan(&r.ID, &r.DisplayName, &r.Engine, &r.Host, &r.Port, &r.DBServerHost, &r.Database, &r.TLSMode,
		&r.CredentialRef, &r.ExpectedIdentity, &mode, &r.LabConfirmed, &r.CreatedBy, &r.CreatedAt,
		&passed, &at, &r.IdentityCheck.By, &reasons); err != nil {
		return dbsim.TargetRecord{}, err
	}
	r.Mode = dbsim.ExecMode(mode)
	// "Checked" means a check was recorded: a timestamp exists. Only then can
	// Passed be true, so a row with passed=true but no timestamp is not a pass.
	if at != nil {
		r.IdentityCheck.Checked = true
		r.IdentityCheck.Passed = passed
		r.IdentityCheck.At = *at
	}
	if len(reasons) > 0 {
		_ = json.Unmarshal(reasons, &r.IdentityCheck.Reasons)
	}
	return r, nil
}

// Create stores a new target; dbsim.ErrTargetExists on a duplicate id.
func (s DBSimTargetStore) Create(ctx context.Context, r dbsim.TargetRecord) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO dbsim_targets (id, display_name, engine, host, port, db_server_host, database_name, tls_mode,
			credential_ref, expected_identity, mode, lab_confirmed, created_by, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		r.ID, r.DisplayName, r.Engine, r.Host, r.Port, r.DBServerHost, r.Database, r.TLSMode,
		r.CredentialRef, r.ExpectedIdentity, string(r.Mode), r.LabConfirmed, r.CreatedBy, r.CreatedAt)
	if err != nil {
		var pgErr interface{ SQLState() string }
		if errors.As(err, &pgErr) && pgErr.SQLState() == "23505" {
			return dbsim.ErrTargetExists
		}
		return fmt.Errorf("create dbsim target: %w", err)
	}
	return nil
}

// Get returns one target; dbsim.ErrTargetNotFound when absent.
func (s DBSimTargetStore) Get(ctx context.Context, id string) (dbsim.TargetRecord, error) {
	r, err := scanDBSimTarget(s.Pool.QueryRow(ctx, `SELECT `+dbsimTargetCols+` FROM dbsim_targets WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return dbsim.TargetRecord{}, dbsim.ErrTargetNotFound
	}
	if err != nil {
		return dbsim.TargetRecord{}, fmt.Errorf("get dbsim target: %w", err)
	}
	return r, nil
}

// List returns every target ordered by id.
func (s DBSimTargetStore) List(ctx context.Context) ([]dbsim.TargetRecord, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+dbsimTargetCols+` FROM dbsim_targets ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list dbsim targets: %w", err)
	}
	defer rows.Close()
	var out []dbsim.TargetRecord
	for rows.Next() {
		r, err := scanDBSimTarget(rows)
		if err != nil {
			return nil, fmt.Errorf("list dbsim targets: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Delete removes a target; dbsim.ErrTargetNotFound when absent.
func (s DBSimTargetStore) Delete(ctx context.Context, id string) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM dbsim_targets WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete dbsim target: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return dbsim.ErrTargetNotFound
	}
	return nil
}

// SaveIdentityCheck records the latest read-only identity check of a target
// (result, when, by whom, reasons). It replaces any earlier result.
func (s DBSimTargetStore) SaveIdentityCheck(ctx context.Context, id string, st dbsim.IdentityCheckState) error {
	reasons := st.Reasons
	if reasons == nil {
		reasons = []string{}
	}
	rb, err := json.Marshal(reasons)
	if err != nil {
		return fmt.Errorf("save dbsim identity check: %w", err)
	}
	tag, err := s.Pool.Exec(ctx, `
		UPDATE dbsim_targets
		SET identity_check_passed = $2, identity_check_at = $3, identity_check_by = $4, identity_check_reasons = $5::jsonb
		WHERE id = $1`, id, st.Passed && st.Checked, st.At, st.By, string(rb))
	if err != nil {
		return fmt.Errorf("save dbsim identity check: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return dbsim.ErrTargetNotFound
	}
	return nil
}

// DBSimTargetResolver is a dbsim.TargetResolver over the registry: the only
// production source of a Target's trust flags.
type DBSimTargetResolver struct{ Store DBSimTargetStore }

// Resolve implements dbsim.TargetResolver.
func (r DBSimTargetResolver) Resolve(ctx context.Context, id string) (dbsim.Target, error) {
	rec, err := r.Store.Get(ctx, id)
	if err != nil {
		if errors.Is(err, dbsim.ErrTargetNotFound) {
			return dbsim.Target{}, fmt.Errorf("%w: %q", dbsim.ErrTargetNotFound, id)
		}
		return dbsim.Target{}, err
	}
	return rec.ToTarget(), nil
}

// DBSimSettingsStore is the Postgres-backed store of the Admin switches (it
// satisfies dbadmin.SettingsStore structurally).
type DBSimSettingsStore struct{ Pool *pgxpool.Pool }

// GetClientMode returns the raw stored value of the DB client mode setting.
func (s DBSimSettingsStore) GetClientMode(ctx context.Context) (string, bool, error) {
	var v string
	err := s.Pool.QueryRow(ctx, `SELECT value FROM dbsim_settings WHERE key = $1`, dbsim.ClientModeSettingKey).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("get dbsim client mode: %w", err)
	}
	return v, true, nil
}

// SetClientMode stores the DB client mode setting ("true" or "false").
func (s DBSimSettingsStore) SetClientMode(ctx context.Context, enabled bool, by string) error {
	v := "false"
	if enabled {
		v = "true"
	}
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO dbsim_settings (key, value, updated_by) VALUES ($1, $2, $3)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW(), updated_by = EXCLUDED.updated_by`,
		dbsim.ClientModeSettingKey, v, by)
	if err != nil {
		return fmt.Errorf("set dbsim client mode: %w", err)
	}
	return nil
}
