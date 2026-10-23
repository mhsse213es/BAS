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
	"github.com/audspect/bas/internal/dbsim/dbadmin"
)

// insertDBSimAudit writes one audit_logs row inside tx, so a state change and
// its audit row commit or roll back together. The row has the same shape as
// api.Handler.auditLogAs writes.
func insertDBSimAudit(ctx context.Context, tx pgx.Tx, e dbadmin.AuditEntry) error {
	detail := []byte("{}")
	if e.Detail != nil {
		b, err := json.Marshal(e.Detail)
		if err != nil {
			return fmt.Errorf("audit detail: %w", err)
		}
		detail = b
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_logs (actor_id, action, resource, detail, ip, outcome) VALUES ($1,$2,$3,$4,$5,$6)`,
		e.ActorID, e.Action, e.Resource, detail, e.IP, e.Outcome); err != nil {
		return fmt.Errorf("audit write: %w", err)
	}
	return nil
}

// withDBSimAuditTx runs fn and the audit insert in one transaction; any error
// rolls both back.
func withDBSimAuditTx(ctx context.Context, pool *pgxpool.Pool, e dbadmin.AuditEntry, fn func(tx pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	if err := insertDBSimAudit(ctx, tx, e); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

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
func (s DBSimTargetStore) Create(ctx context.Context, r dbsim.TargetRecord, audit dbadmin.AuditEntry) error {
	err := withDBSimAuditTx(ctx, s.Pool, audit, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
		INSERT INTO dbsim_targets (id, display_name, engine, host, port, db_server_host, database_name, tls_mode,
			credential_ref, expected_identity, mode, lab_confirmed, created_by, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			r.ID, r.DisplayName, r.Engine, r.Host, r.Port, r.DBServerHost, r.Database, r.TLSMode,
			r.CredentialRef, r.ExpectedIdentity, string(r.Mode), r.LabConfirmed, r.CreatedBy, r.CreatedAt)
		return err
	})
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
func (s DBSimTargetStore) Delete(ctx context.Context, id string, audit dbadmin.AuditEntry) error {
	err := withDBSimAuditTx(ctx, s.Pool, audit, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM dbsim_targets WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return dbsim.ErrTargetNotFound
		}
		return nil
	})
	if err != nil && !errors.Is(err, dbsim.ErrTargetNotFound) {
		return fmt.Errorf("delete dbsim target: %w", err)
	}
	return err
}

// SaveIdentityCheck records the latest read-only identity check (result, when,
// by whom, reasons) together with its audit row. The UPDATE is bound to the
// exact record version the probe ran against: id, creation time and every
// connection/identity field must still match, otherwise nothing is recorded and
// dbsim.ErrTargetChanged is returned (a deleted and re-registered target cannot
// inherit the pass). dbsim.ErrTargetNotFound when the id no longer exists.
func (s DBSimTargetStore) SaveIdentityCheck(ctx context.Context, against dbsim.TargetRecord, st dbsim.IdentityCheckState, audit dbadmin.AuditEntry) error {
	reasons := st.Reasons
	if reasons == nil {
		reasons = []string{}
	}
	rb, err := json.Marshal(reasons)
	if err != nil {
		return fmt.Errorf("save dbsim identity check: %w", err)
	}
	err = withDBSimAuditTx(ctx, s.Pool, audit, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE dbsim_targets
			SET identity_check_passed = $2, identity_check_at = $3, identity_check_by = $4, identity_check_reasons = $5::jsonb
			WHERE id = $1 AND created_at = $6 AND engine = $7 AND host = $8 AND port = $9 AND database_name = $10
			  AND tls_mode = $11 AND credential_ref = $12 AND expected_identity = $13 AND mode = $14 AND db_server_host = $15
			  AND (identity_check_at IS NULL OR identity_check_at <= $3)`,
			against.ID, st.Passed && st.Checked, st.At, st.By, string(rb), against.CreatedAt, against.Engine, against.Host,
			against.Port, against.Database, against.TLSMode, against.CredentialRef, against.ExpectedIdentity,
			string(against.Mode), against.DBServerHost)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			// Zero rows: say why, inside the same transaction (it rolls back, audit row too).
			var sameVersion, exists bool
			if qerr := tx.QueryRow(ctx, `
				SELECT EXISTS (SELECT 1 FROM dbsim_targets WHERE id = $1 AND created_at = $2 AND engine = $3 AND host = $4
				  AND port = $5 AND database_name = $6 AND tls_mode = $7 AND credential_ref = $8 AND expected_identity = $9
				  AND mode = $10 AND db_server_host = $11),
				  EXISTS (SELECT 1 FROM dbsim_targets WHERE id = $1)`,
				against.ID, against.CreatedAt, against.Engine, against.Host, against.Port, against.Database, against.TLSMode,
				against.CredentialRef, against.ExpectedIdentity, string(against.Mode), against.DBServerHost).Scan(&sameVersion, &exists); qerr != nil {
				return qerr
			}
			switch {
			case !exists:
				return dbsim.ErrTargetNotFound
			case sameVersion:
				return dbsim.ErrIdentityCheckSuperseded
			}
			return dbsim.ErrTargetChanged
		}
		return nil
	})
	if err != nil && !errors.Is(err, dbsim.ErrTargetNotFound) && !errors.Is(err, dbsim.ErrTargetChanged) && !errors.Is(err, dbsim.ErrIdentityCheckSuperseded) {
		return fmt.Errorf("save dbsim identity check: %w", err)
	}
	return err
}

// DBSimTargetResolver is a dbsim.TargetResolver over the registry: the only
// production source of a Target's trust flags.
type DBSimTargetResolver struct {
	Store DBSimTargetStore
	// Now and MaxAge default to the real clock and
	// dbsim.DefaultIdentityCheckMaxAge (a placeholder for an open user decision).
	Now    func() time.Time
	MaxAge time.Duration
}

// Resolve implements dbsim.TargetResolver.
func (r DBSimTargetResolver) Resolve(ctx context.Context, id string) (dbsim.Target, error) {
	rec, err := r.Store.Get(ctx, id)
	if err != nil {
		if errors.Is(err, dbsim.ErrTargetNotFound) {
			return dbsim.Target{}, fmt.Errorf("%w: %q", dbsim.ErrTargetNotFound, id)
		}
		return dbsim.Target{}, err
	}
	now, maxAge := time.Now(), r.MaxAge
	if r.Now != nil {
		now = r.Now()
	}
	if maxAge == 0 {
		maxAge = dbsim.DefaultIdentityCheckMaxAge
	}
	return rec.ToTargetAt(now, maxAge), nil
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
func (s DBSimSettingsStore) SetClientMode(ctx context.Context, enabled bool, by string, audit dbadmin.AuditEntry) error {
	v := "false"
	if enabled {
		v = "true"
	}
	err := withDBSimAuditTx(ctx, s.Pool, audit, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO dbsim_settings (key, value, updated_by) VALUES ($1, $2, $3)
			ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW(), updated_by = EXCLUDED.updated_by`,
			dbsim.ClientModeSettingKey, v, by)
		return err
	})
	if err != nil {
		return fmt.Errorf("set dbsim client mode: %w", err)
	}
	return nil
}
