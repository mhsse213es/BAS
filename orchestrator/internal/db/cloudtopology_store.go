package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudtopology"
)

// EnsureCloudTopologySchema creates the cloud_topology_imports table.
func EnsureCloudTopologySchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS cloud_topology_imports (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			source_type    text        NOT NULL,
			imported_by    text,
			imported_at    timestamptz NOT NULL DEFAULT NOW(),
			config_version text,
			limitations    text[],
			topology_data  jsonb       NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("cloud_topology_imports: ensure schema: %w", err)
	}
	return nil
}

// cloudTopologyData is the shape persisted in the topology_data jsonb
// column -- just the six slices that make an import's content, not
// its metadata (which live in their own columns).
type cloudTopologyData struct {
	Networks []cloudtopology.CloudNetwork      `json:"networks"`
	Subnets  []cloudtopology.CloudSubnet       `json:"subnets"`
	Groups   []cloudtopology.SecurityGroup     `json:"groups"`
	Rules    []cloudtopology.SecurityGroupRule `json:"rules"`
	Routes   []cloudtopology.RouteTableEntry   `json:"routes"`
	Peerings []cloudtopology.PeeringConnection `json:"peerings"`
}

// InsertCloudTopologyImport writes a new cloud_topology_imports row.
// The caller supplies imp.ID already generated.
func InsertCloudTopologyImport(ctx context.Context, pool *pgxpool.Pool, imp *cloudtopology.CloudTopologyImport) error {
	data, err := json.Marshal(cloudTopologyData{
		Networks: imp.Networks, Subnets: imp.Subnets, Groups: imp.Groups,
		Rules: imp.Rules, Routes: imp.Routes, Peerings: imp.Peerings,
	})
	if err != nil {
		return fmt.Errorf("cloud_topology_imports: marshal topology data for %s: %w", imp.ID, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO cloud_topology_imports (id, source_type, imported_by, config_version, limitations, topology_data)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		imp.ID, imp.SourceType, nullableString(imp.ImportedBy), nullableString(imp.ConfigVersion), imp.Limitations, data)
	if err != nil {
		return fmt.Errorf("cloud_topology_imports: insert %s: %w", imp.ID, err)
	}
	return nil
}

func scanCloudTopologyImport(row pgx.Row) (*cloudtopology.CloudTopologyImport, error) {
	imp := &cloudtopology.CloudTopologyImport{}
	var importedBy, configVersion *string
	var data []byte
	if err := row.Scan(&imp.ID, &imp.SourceType, &importedBy, &imp.ImportedAt, &configVersion, &imp.Limitations, &data); err != nil {
		return nil, err
	}
	if importedBy != nil {
		imp.ImportedBy = *importedBy
	}
	if configVersion != nil {
		imp.ConfigVersion = *configVersion
	}
	var td cloudTopologyData
	if err := json.Unmarshal(data, &td); err != nil {
		return nil, fmt.Errorf("cloud_topology_imports: unmarshal topology data for %s: %w", imp.ID, err)
	}
	imp.Networks, imp.Subnets, imp.Groups = td.Networks, td.Subnets, td.Groups
	imp.Rules, imp.Routes, imp.Peerings = td.Rules, td.Routes, td.Peerings
	return imp, nil
}

// GetCloudTopologyImport returns one import by id. A missing id
// returns an error satisfying errors.Is(err, pgx.ErrNoRows).
func GetCloudTopologyImport(ctx context.Context, pool *pgxpool.Pool, id string) (*cloudtopology.CloudTopologyImport, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, topology_data
		 FROM cloud_topology_imports WHERE id = $1`, id)
	imp, err := scanCloudTopologyImport(row)
	if err != nil {
		return nil, fmt.Errorf("cloud_topology_imports: get %s: %w", id, err)
	}
	return imp, nil
}

// ListCloudTopologyImports returns up to limit rows, newest first.
func ListCloudTopologyImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*cloudtopology.CloudTopologyImport, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, topology_data
		 FROM cloud_topology_imports ORDER BY imported_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("cloud_topology_imports: list: %w", err)
	}
	defer rows.Close()
	var out []*cloudtopology.CloudTopologyImport
	for rows.Next() {
		imp, err := scanCloudTopologyImport(rows)
		if err != nil {
			return nil, fmt.Errorf("cloud_topology_imports: list scan: %w", err)
		}
		out = append(out, imp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cloud_topology_imports: list rows: %w", err)
	}
	return out, nil
}
