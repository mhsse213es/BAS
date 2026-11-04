package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The fourteen plaintext credential columns, each with its reference column. The count is the inventory in the QA log.
var wantRefColumns = []string{
	"siem_configs.token_ref", "siem_configs.password_ref", "siem_configs.client_secret_ref",
	"detection_connectors.client_secret_ref", "detection_connectors.api_token_ref",
	"action_connectors.client_secret_ref", "action_connectors.api_token_ref",
	"threat_intel_config.api_key_ref",
	"openaev_config.bearer_token_ref",
	"taxii_connector_config.password_ref", "taxii_connector_config.client_cert_ref", "taxii_connector_config.client_key_ref",
	"sso_configs.client_secret_ref",
	"notification_webhooks.secret_ref",
}

func TestEnsureSecretStoreSchemaAddsReferenceColumns(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	tdb.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		// Run twice: the step must be idempotent.
		for i := range 2 {
			if err := db.EnsureSecretStoreSchema(ctx, pool); err != nil {
				t.Fatalf("run %d: %v", i+1, err)
			}
		}
		for _, qualified := range wantRefColumns {
			var table, column string
			for i := range qualified {
				if qualified[i] == '.' {
					table, column = qualified[:i], qualified[i+1:]
					break
				}
			}
			var n int
			if err := pool.QueryRow(ctx,
				`SELECT count(*) FROM information_schema.columns
				  WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2
				    AND data_type = 'text' AND is_nullable = 'NO'`,
				table, column).Scan(&n); err != nil {
				t.Fatalf("%s: %v", qualified, err)
			}
			if n != 1 {
				t.Errorf("%s: not present as a NOT NULL text column", qualified)
			}
		}
		var tableCount int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'credential_secrets'`,
		).Scan(&tableCount); err != nil || tableCount != 1 {
			t.Errorf("credential_secrets table: count %d, err %v", tableCount, err)
		}
	})
}
