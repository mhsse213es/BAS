package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/networkpolicy"
)

// EnsureNetworkPolicySchema creates the network_policy_imports table.
func EnsureNetworkPolicySchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS network_policy_imports (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			source_type    text        NOT NULL,
			imported_by    text,
			imported_at    timestamptz NOT NULL DEFAULT NOW(),
			config_version text,
			default_policy text        NOT NULL,
			limitations    text[],
			policy_data    jsonb       NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("network_policy_imports: ensure schema: %w", err)
	}
	return nil
}

// policyData is the shape persisted in the policy_data jsonb column --
// just the two slices that make an import's content, not its metadata
// (which live in their own columns).
type policyData struct {
	Zones []networkpolicy.Zone `json:"zones"`
	Rules []networkpolicy.Rule `json:"rules"`
}

// InsertNetworkPolicyImport writes a new network_policy_imports row. The
// caller supplies imp.ID already generated.
func InsertNetworkPolicyImport(ctx context.Context, pool *pgxpool.Pool, imp *networkpolicy.PolicyImport) error {
	data, err := json.Marshal(policyData{Zones: imp.Zones, Rules: imp.Rules})
	if err != nil {
		return fmt.Errorf("network_policy_imports: marshal policy data for %s: %w", imp.ID, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO network_policy_imports (id, source_type, imported_by, config_version, default_policy, limitations, policy_data)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		imp.ID, imp.SourceType, nullableString(imp.ImportedBy), nullableString(imp.ConfigVersion), string(imp.DefaultPolicy), imp.Limitations, data)
	if err != nil {
		return fmt.Errorf("network_policy_imports: insert %s: %w", imp.ID, err)
	}
	return nil
}

func scanNetworkPolicyImport(row pgx.Row) (*networkpolicy.PolicyImport, error) {
	imp := &networkpolicy.PolicyImport{}
	var importedBy, configVersion *string
	var defaultPolicy string
	var data []byte
	if err := row.Scan(&imp.ID, &imp.SourceType, &importedBy, &imp.ImportedAt, &configVersion, &defaultPolicy, &imp.Limitations, &data); err != nil {
		return nil, err
	}
	if importedBy != nil {
		imp.ImportedBy = *importedBy
	}
	if configVersion != nil {
		imp.ConfigVersion = *configVersion
	}
	imp.DefaultPolicy = networkpolicy.DefaultPolicy(defaultPolicy)
	var pd policyData
	if err := json.Unmarshal(data, &pd); err != nil {
		return nil, fmt.Errorf("network_policy_imports: unmarshal policy data for %s: %w", imp.ID, err)
	}
	imp.Zones = pd.Zones
	imp.Rules = pd.Rules
	return imp, nil
}

// GetNetworkPolicyImport returns one import by id. A missing id returns
// an error satisfying errors.Is(err, pgx.ErrNoRows).
func GetNetworkPolicyImport(ctx context.Context, pool *pgxpool.Pool, id string) (*networkpolicy.PolicyImport, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, default_policy, limitations, policy_data
		 FROM network_policy_imports WHERE id = $1`, id)
	imp, err := scanNetworkPolicyImport(row)
	if err != nil {
		return nil, fmt.Errorf("network_policy_imports: get %s: %w", id, err)
	}
	return imp, nil
}

// ListNetworkPolicyImports returns up to limit rows, newest first.
func ListNetworkPolicyImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*networkpolicy.PolicyImport, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, default_policy, limitations, policy_data
		 FROM network_policy_imports ORDER BY imported_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("network_policy_imports: list: %w", err)
	}
	defer rows.Close()
	var out []*networkpolicy.PolicyImport
	for rows.Next() {
		imp, err := scanNetworkPolicyImport(rows)
		if err != nil {
			return nil, fmt.Errorf("network_policy_imports: list scan: %w", err)
		}
		out = append(out, imp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("network_policy_imports: list rows: %w", err)
	}
	return out, nil
}
