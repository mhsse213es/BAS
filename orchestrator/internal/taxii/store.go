package taxii

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned by Get/Update when the row doesn't exist.
var ErrNotFound = errors.New("taxii connector config not found")

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

const configCols = `id, name, server_url, api_root, collection_id, auth_type, username, password,
	client_cert, client_key, enabled, last_poll_at, last_poll_status, last_poll_summary, last_error,
	created_at, updated_at`

func scanConfig(row interface {
	Scan(dest ...any) error
}) (ConnectorConfig, error) {
	var c ConnectorConfig
	var summaryJSON []byte
	err := row.Scan(&c.ID, &c.Name, &c.ServerURL, &c.APIRoot, &c.CollectionID, &c.AuthType, &c.Username,
		&c.Password, &c.ClientCert, &c.ClientKey, &c.Enabled, &c.LastPollAt, &c.LastPollStatus, &summaryJSON,
		&c.LastError, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return ConnectorConfig{}, err
	}
	_ = json.Unmarshal(summaryJSON, &c.LastPollSummary)
	return c, nil
}

func (s *Store) Create(ctx context.Context, c ConnectorConfig) (ConnectorConfig, error) {
	if c.AuthType == "" {
		c.AuthType = "none"
	}
	row := s.pool.QueryRow(ctx,
		`INSERT INTO taxii_connector_config (name, server_url, api_root, collection_id, auth_type, username, password, client_cert, client_key, enabled)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 RETURNING `+configCols,
		c.Name, c.ServerURL, c.APIRoot, c.CollectionID, c.AuthType, c.Username, c.Password, c.ClientCert, c.ClientKey, c.Enabled)
	return scanConfig(row)
}

func (s *Store) Get(ctx context.Context, id string) (ConnectorConfig, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+configCols+` FROM taxii_connector_config WHERE id = $1`, id)
	c, err := scanConfig(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConnectorConfig{}, ErrNotFound
	}
	return c, err
}

func (s *Store) List(ctx context.Context) ([]ConnectorConfig, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+configCols+` FROM taxii_connector_config ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConnectorConfig
	for rows.Next() {
		c, err := scanConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) ListEnabled(ctx context.Context) ([]ConnectorConfig, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+configCols+` FROM taxii_connector_config WHERE enabled = true ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConnectorConfig
	for rows.Next() {
		c, err := scanConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Update applies every plain field from c, keeping the stored secret value
// for any of password/clientCert/clientKey whose keep* flag is true --
// matching PutThreatIntelConfig's "empty submitted value keeps current"
// convention at the store layer instead of the handler layer, since TAXII
// has three independent secrets instead of MISP/OTX's one.
func (s *Store) Update(ctx context.Context, id string, c ConnectorConfig, keepPassword, keepClientCert, keepClientKey bool) (ConnectorConfig, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE taxii_connector_config SET
		   name = $2, server_url = $3, api_root = $4, collection_id = $5, auth_type = $6, username = $7,
		   password = CASE WHEN $8 THEN password ELSE $9 END,
		   client_cert = CASE WHEN $10 THEN client_cert ELSE $11 END,
		   client_key = CASE WHEN $12 THEN client_key ELSE $13 END,
		   enabled = $14, updated_at = NOW()
		 WHERE id = $1
		 RETURNING `+configCols,
		id, c.Name, c.ServerURL, c.APIRoot, c.CollectionID, c.AuthType, c.Username,
		keepPassword, c.Password, keepClientCert, c.ClientCert, keepClientKey, c.ClientKey, c.Enabled)
	updated, err := scanConfig(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConnectorConfig{}, ErrNotFound
	}
	return updated, err
}

func (s *Store) Delete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM taxii_connector_config WHERE id = $1`, id)
	return err
}

func (s *Store) RecordPollResult(ctx context.Context, id, status string, summary PollSummary, errMsg string) error {
	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE taxii_connector_config SET last_poll_at = NOW(), last_poll_status = $2, last_poll_summary = $3, last_error = $4 WHERE id = $1`,
		id, status, summaryJSON, errMsg)
	return err
}

func (s *Store) HasIngested(ctx context.Context, connectorID, stixID string, modified time.Time) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM taxii_ingested_objects WHERE connector_id = $1 AND stix_id = $2 AND modified = $3)`,
		connectorID, stixID, modified,
	).Scan(&exists)
	return exists, err
}

func (s *Store) RecordIngested(ctx context.Context, connectorID, stixID string, modified time.Time, iocID string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO taxii_ingested_objects (connector_id, stix_id, modified, ioc_id) VALUES ($1,$2,$3,$4)
		 ON CONFLICT (connector_id, stix_id, modified) DO NOTHING`,
		connectorID, stixID, modified, iocID)
	return err
}
