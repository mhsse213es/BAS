package db

import (
	"context"
	"fmt"

	"github.com/audspect/bas/internal/secretstore"
	"github.com/jackc/pgx/v5/pgxpool"
)

// credentialReferenceColumns lists every plaintext credential column the secret store will replace. Each gets a sibling
// "<column>_ref" column that holds the reference to its value in credential_secrets. Phase 1 only adds the columns; the
// plaintext columns are still read and written until the migration job and its verification have run.
var credentialReferenceColumns = map[string][]string{
	"siem_configs":           {"token", "password", "client_secret"},
	"detection_connectors":   {"client_secret", "api_token"},
	"action_connectors":      {"client_secret", "api_token"},
	"threat_intel_config":    {"api_key"},
	"openaev_config":         {"bearer_token"},
	"taxii_connector_config": {"password", "client_cert", "client_key"},
	"sso_configs":            {"client_secret"},
	"notification_webhooks":  {"secret"},
}

// EnsureSecretStoreSchema creates the secret store table and adds the reference columns. It is idempotent.
func EnsureSecretStoreSchema(ctx context.Context, pool *pgxpool.Pool) error {
	for _, stmt := range secretstore.SchemaSQL {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("secret store table: %w", err)
		}
	}
	for table, cols := range credentialReferenceColumns {
		for _, col := range cols {
			stmt := fmt.Sprintf(
				"ALTER TABLE IF EXISTS %s ADD COLUMN IF NOT EXISTS %s_ref text NOT NULL DEFAULT ''",
				table, col)
			if _, err := pool.Exec(ctx, stmt); err != nil {
				return fmt.Errorf("reference column %s.%s_ref: %w", table, col, err)
			}
		}
	}
	return nil
}
