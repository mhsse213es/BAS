package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/networktopology"
)

// EnsureNetworkTopologySchema creates the network_topology_imports table.
func EnsureNetworkTopologySchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS network_topology_imports (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			source_type    text        NOT NULL,
			imported_by    text,
			imported_at    timestamptz NOT NULL DEFAULT NOW(),
			config_version text,
			limitations    text[],
			topology_data  jsonb       NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("network_topology_imports: ensure schema: %w", err)
	}
	return nil
}

// topologyData is the shape persisted in the topology_data jsonb column
// -- just the two slices that make an import's content, not its
// metadata (which live in their own columns).
type topologyData struct {
	Zones []networktopology.Zone      `json:"zones"`
	Edges []networktopology.RouteEdge `json:"edges"`
}

// InsertNetworkTopologyImport writes a new network_topology_imports
// row. The caller supplies imp.ID already generated.
func InsertNetworkTopologyImport(ctx context.Context, pool *pgxpool.Pool, imp *networktopology.TopologyImport) error {
	data, err := json.Marshal(topologyData{Zones: imp.Zones, Edges: imp.Edges})
	if err != nil {
		return fmt.Errorf("network_topology_imports: marshal topology data for %s: %w", imp.ID, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO network_topology_imports (id, source_type, imported_by, config_version, limitations, topology_data)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		imp.ID, imp.SourceType, nullableString(imp.ImportedBy), nullableString(imp.ConfigVersion), imp.Limitations, data)
	if err != nil {
		return fmt.Errorf("network_topology_imports: insert %s: %w", imp.ID, err)
	}
	return nil
}

func scanNetworkTopologyImport(row pgx.Row) (*networktopology.TopologyImport, error) {
	imp := &networktopology.TopologyImport{}
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
	var td topologyData
	if err := json.Unmarshal(data, &td); err != nil {
		return nil, fmt.Errorf("network_topology_imports: unmarshal topology data for %s: %w", imp.ID, err)
	}
	imp.Zones = td.Zones
	imp.Edges = td.Edges
	return imp, nil
}

// GetNetworkTopologyImport returns one import by id. A missing id
// returns an error satisfying errors.Is(err, pgx.ErrNoRows).
func GetNetworkTopologyImport(ctx context.Context, pool *pgxpool.Pool, id string) (*networktopology.TopologyImport, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, topology_data
		 FROM network_topology_imports WHERE id = $1`, id)
	imp, err := scanNetworkTopologyImport(row)
	if err != nil {
		return nil, fmt.Errorf("network_topology_imports: get %s: %w", id, err)
	}
	return imp, nil
}

// ListNetworkTopologyImports returns up to limit rows, newest first.
func ListNetworkTopologyImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*networktopology.TopologyImport, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, topology_data
		 FROM network_topology_imports ORDER BY imported_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("network_topology_imports: list: %w", err)
	}
	defer rows.Close()
	var out []*networktopology.TopologyImport
	for rows.Next() {
		imp, err := scanNetworkTopologyImport(rows)
		if err != nil {
			return nil, fmt.Errorf("network_topology_imports: list scan: %w", err)
		}
		out = append(out, imp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("network_topology_imports: list rows: %w", err)
	}
	return out, nil
}
