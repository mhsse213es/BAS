package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/k8sscenario"
)

// ErrAuthorizationNotFound is returned when no customer authorization has the given ID.
var ErrAuthorizationNotFound = errors.New("customer authorization not found")

// ErrAuthorizationRevoked is returned when revoking a record that is already revoked.
var ErrAuthorizationRevoked = errors.New("customer authorization is already revoked")

// ErrCustomerNotFound is returned when the customer reference does not name an active tenant.
var ErrCustomerNotFound = errors.New("customerRef must name an active tenant")

// EnsureK8sAuthorizationSchema creates the customer authorization table. Idempotent. Records reference the cluster
// registry, so an authorization cannot name a cluster that does not exist. There is no delete path in the store:
// a record is revoked, never removed, so the history stays.
func EnsureK8sAuthorizationSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS k8s_customer_authorizations (
			id             text        PRIMARY KEY,
			cluster_id     text        NOT NULL REFERENCES k8s_clusters(id),
			customer_ref   text        NOT NULL,
			authorized_by  text        NOT NULL,
			authorized_at  timestamptz NOT NULL,
			expires_at     timestamptz NOT NULL,
			scenarios      text[]      NOT NULL,
			namespaces     text[]      NOT NULL,
			revoked_at     timestamptz,
			revoked_by     text        NOT NULL DEFAULT '',
			CHECK (cardinality(scenarios) > 0),
			CHECK (cardinality(namespaces) > 0),
			CHECK (expires_at > authorized_at)
		)`,
		`CREATE INDEX IF NOT EXISTS k8s_customer_authorizations_cluster
			ON k8s_customer_authorizations (cluster_id)`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("k8s authorization schema: %w", err)
		}
	}
	return nil
}

// K8sAuthorizationStore is the Postgres-backed customer authorization store.
type K8sAuthorizationStore struct {
	pool *pgxpool.Pool
}

// NewK8sAuthorizationStore returns a store over the pool.
func NewK8sAuthorizationStore(pool *pgxpool.Pool) *K8sAuthorizationStore {
	return &K8sAuthorizationStore{pool: pool}
}

// InsertWithAudit stores a new record and its creation audit event in one transaction. If the audit row cannot be
// written, the record is not stored either, so there is never an active authorization without its audit event.
// The customer reference must name an active tenant; that is checked in the same statement as the insert.
func (s *K8sAuthorizationStore) InsertWithAudit(ctx context.Context, a k8sscenario.CustomerAuthorization, ev k8sscenario.Event) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
		INSERT INTO k8s_customer_authorizations
			(id, cluster_id, customer_ref, authorized_by, authorized_at, expires_at, scenarios, namespaces)
		SELECT $1, $2, $3::text, $4, $5, $6, $7, $8
		WHERE EXISTS (SELECT 1 FROM tenants WHERE id = $3::text AND status = 'active')`,
		a.ID, a.ClusterID, a.CustomerRef, a.AuthorizedBy, a.AuthorizedAt, a.ExpiresAt, a.Scenarios, a.Namespaces)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrCustomerNotFound
	}
	if err := writeScenarioAuditRow(ctx, tx, ev); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Get returns one record by ID.
func (s *K8sAuthorizationStore) Get(ctx context.Context, id string) (k8sscenario.CustomerAuthorization, bool, error) {
	row := s.pool.QueryRow(ctx, authorizationSelect+` WHERE id = $1`, id)
	a, err := scanAuthorization(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return k8sscenario.CustomerAuthorization{}, false, nil
	}
	if err != nil {
		return k8sscenario.CustomerAuthorization{}, false, err
	}
	return a, true, nil
}

// List returns the records for one cluster, or every record when clusterID is empty. Newest first.
func (s *K8sAuthorizationStore) List(ctx context.Context, clusterID string) ([]k8sscenario.CustomerAuthorization, error) {
	query := authorizationSelect + ` WHERE $1 = '' OR cluster_id = $1 ORDER BY authorized_at DESC, id`
	rows, err := s.pool.Query(ctx, query, clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []k8sscenario.CustomerAuthorization
	for rows.Next() {
		a, err := scanAuthorization(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RevokeWithAudit marks a record revoked and writes its revoke audit event in one transaction. The update applies only
// while the record is not revoked, so two concurrent revokes cannot both succeed. An unknown ID returns
// ErrAuthorizationNotFound; a revoked one ErrAuthorizationRevoked. On any error nothing changes.
func (s *K8sAuthorizationStore) RevokeWithAudit(ctx context.Context, id, revokedBy string, at time.Time, ev k8sscenario.Event) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
		UPDATE k8s_customer_authorizations SET revoked_at = $2, revoked_by = $3
		WHERE id = $1 AND revoked_at IS NULL`, id, at.UTC(), revokedBy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM k8s_customer_authorizations WHERE id = $1)`, id).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrAuthorizationNotFound
		}
		return ErrAuthorizationRevoked
	}
	if err := writeScenarioAuditRow(ctx, tx, ev); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const authorizationSelect = `SELECT id, cluster_id, customer_ref, authorized_by, authorized_at, expires_at,
	scenarios, namespaces, revoked_at, revoked_by FROM k8s_customer_authorizations`

func scanAuthorization(row rowScanner) (k8sscenario.CustomerAuthorization, error) {
	var a k8sscenario.CustomerAuthorization
	var revokedAt *time.Time
	if err := row.Scan(&a.ID, &a.ClusterID, &a.CustomerRef, &a.AuthorizedBy, &a.AuthorizedAt, &a.ExpiresAt,
		&a.Scenarios, &a.Namespaces, &revokedAt, &a.RevokedBy); err != nil {
		return k8sscenario.CustomerAuthorization{}, err
	}
	a.RevokedAt = revokedAt
	return a, nil
}
