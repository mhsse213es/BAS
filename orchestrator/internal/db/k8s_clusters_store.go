package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/k8sscenario"
)

// ErrK8sClusterExists is returned when a display name or server URL is already registered.
var ErrK8sClusterExists = errors.New("a cluster with this display name or server URL is already registered")

// EnsureK8sClusterSchema creates the cluster registry table. Idempotent.
// The unique constraints stop two clusters with the same display name, or the same API server, being confused.
func EnsureK8sClusterSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS k8s_clusters (
			id            text        PRIMARY KEY,
			display_name  text        NOT NULL UNIQUE,
			server_url    text        NOT NULL UNIQUE,
			class         text        NOT NULL CHECK (class IN ('lab', 'non-production', 'production')),
			created_at    timestamptz NOT NULL DEFAULT NOW()
		)`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("k8s cluster schema: %w", err)
		}
	}
	return nil
}

// K8sClusterStore is the Postgres-backed cluster registry.
type K8sClusterStore struct {
	pool *pgxpool.Pool
}

// NewK8sClusterStore returns a store over the pool.
func NewK8sClusterStore(pool *pgxpool.Pool) *K8sClusterStore {
	return &K8sClusterStore{pool: pool}
}

// Insert stores a validated cluster. A duplicate display name or server URL returns ErrK8sClusterExists.
func (s *K8sClusterStore) Insert(ctx context.Context, c k8sscenario.ClusterRecord) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO k8s_clusters (id, display_name, server_url, class)
		VALUES ($1, $2, $3, $4)`,
		c.ID, c.DisplayName, c.ServerURL, c.Class)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrK8sClusterExists
	}
	return err
}

// List returns all registered clusters ordered by display name.
func (s *K8sClusterStore) List(ctx context.Context) ([]k8sscenario.ClusterRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, display_name, server_url, class FROM k8s_clusters ORDER BY display_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []k8sscenario.ClusterRecord
	for rows.Next() {
		var c k8sscenario.ClusterRecord
		if err := rows.Scan(&c.ID, &c.DisplayName, &c.ServerURL, &c.Class); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Get returns one cluster by its registration ID.
func (s *K8sClusterStore) Get(ctx context.Context, id string) (k8sscenario.ClusterRecord, bool, error) {
	var c k8sscenario.ClusterRecord
	err := s.pool.QueryRow(ctx, `
		SELECT id, display_name, server_url, class FROM k8s_clusters WHERE id = $1`, id).
		Scan(&c.ID, &c.DisplayName, &c.ServerURL, &c.Class)
	if errors.Is(err, pgx.ErrNoRows) {
		return k8sscenario.ClusterRecord{}, false, nil
	}
	if err != nil {
		return k8sscenario.ClusterRecord{}, false, err
	}
	return c, true, nil
}
