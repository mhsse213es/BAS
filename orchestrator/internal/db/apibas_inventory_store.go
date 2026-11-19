package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxAPIBASInventoryVersions is how many inventory versions a target keeps. A new import beyond it removes the oldest.
const MaxAPIBASInventoryVersions = 50

// ErrAPIBASInventoryNotFound means the target has no inventory, or not the requested version.
var ErrAPIBASInventoryNotFound = errors.New("apibas inventory not found")

// APIBASInventory is one imported inventory version of a target's API specification. Body is the inventory as JSON (names and
// shapes of operations; see internal/apibas/openapi). The source document itself is never stored: a specification can carry a
// secret in an example, and only its SHA-256 is kept so an identical re-import is recognised.
type APIBASInventory struct {
	ID             string
	TargetID       string
	Version        int
	ImportedBy     string
	ImportedAt     time.Time
	SourceSHA256   string
	SourceBytes    int
	Title          string
	APIVersion     string
	OpenAPIVersion string
	Operations     int
	Body           []byte
}

// SaveAPIBASInventory stores rec as the target's next inventory version and returns it, together with the version before it
// (Version 0 and nil Body when there was none). When the newest version has the same source hash, nothing is written and that
// version is returned with unchanged true. The target row is locked for the duration, so concurrent imports get distinct
// versions and the prune cannot race.
func SaveAPIBASInventory(ctx context.Context, pool *pgxpool.Pool, rec APIBASInventory) (saved, previous APIBASInventory, unchanged bool, err error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return saved, previous, false, fmt.Errorf("begin inventory save: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var locked string
	if err := tx.QueryRow(ctx, `SELECT id FROM apibas_targets WHERE id = $1 FOR UPDATE`, rec.TargetID).Scan(&locked); errors.Is(err, pgx.ErrNoRows) {
		return saved, previous, false, ErrAPIBASTargetNotFound
	} else if err != nil {
		return saved, previous, false, fmt.Errorf("lock apibas target: %w", err)
	}

	newest, err := scanInventory(tx.QueryRow(ctx, inventorySelect+` WHERE target_id = $1 ORDER BY version DESC LIMIT 1`, rec.TargetID), true)
	switch {
	case errors.Is(err, ErrAPIBASInventoryNotFound):
	case err != nil:
		return saved, previous, false, err
	default:
		previous = newest
		if newest.SourceSHA256 == rec.SourceSHA256 {
			return newest, previous, true, nil
		}
	}

	rec.Version = previous.Version + 1
	err = tx.QueryRow(ctx, `
		INSERT INTO apibas_target_inventories
			(target_id, version, imported_by, source_sha256, source_bytes, title, api_version, openapi_version, operations, body)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
		RETURNING id::text, imported_at`,
		rec.TargetID, rec.Version, rec.ImportedBy, rec.SourceSHA256, rec.SourceBytes, rec.Title, rec.APIVersion, rec.OpenAPIVersion,
		rec.Operations, string(rec.Body)).Scan(&rec.ID, &rec.ImportedAt)
	if err != nil {
		return saved, previous, false, fmt.Errorf("insert apibas inventory: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM apibas_target_inventories WHERE target_id = $1 AND version <= $2`,
		rec.TargetID, rec.Version-MaxAPIBASInventoryVersions); err != nil {
		return saved, previous, false, fmt.Errorf("prune apibas inventories: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return saved, previous, false, fmt.Errorf("commit apibas inventory: %w", err)
	}
	return rec, previous, false, nil
}

const inventorySelect = `SELECT id::text, target_id, version, imported_by, imported_at, source_sha256, source_bytes, title, api_version,
	openapi_version, operations, body::text FROM apibas_target_inventories`

// inventoryListSelect is inventorySelect without the body, so listing versions does not read every stored inventory.
const inventoryListSelect = `SELECT id::text, target_id, version, imported_by, imported_at, source_sha256, source_bytes, title, api_version,
	openapi_version, operations, '' FROM apibas_target_inventories`

func scanInventory(row pgx.Row, withBody bool) (APIBASInventory, error) {
	var r APIBASInventory
	var body string
	err := row.Scan(&r.ID, &r.TargetID, &r.Version, &r.ImportedBy, &r.ImportedAt, &r.SourceSHA256, &r.SourceBytes, &r.Title,
		&r.APIVersion, &r.OpenAPIVersion, &r.Operations, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIBASInventory{}, ErrAPIBASInventoryNotFound
	}
	if err != nil {
		return APIBASInventory{}, fmt.Errorf("read apibas inventory: %w", err)
	}
	if withBody {
		r.Body = []byte(body)
	}
	return r, nil
}

// GetAPIBASInventory returns one inventory version of a target. Version 0 means the newest.
func GetAPIBASInventory(ctx context.Context, pool *pgxpool.Pool, targetID string, version int) (APIBASInventory, error) {
	if version <= 0 {
		return scanInventory(pool.QueryRow(ctx, inventorySelect+` WHERE target_id = $1 ORDER BY version DESC LIMIT 1`, targetID), true)
	}
	return scanInventory(pool.QueryRow(ctx, inventorySelect+` WHERE target_id = $1 AND version = $2`, targetID, version), true)
}

// ListAPIBASInventoryVersions returns a target's inventory versions, newest first, without their bodies.
func ListAPIBASInventoryVersions(ctx context.Context, pool *pgxpool.Pool, targetID string) ([]APIBASInventory, error) {
	rows, err := pool.Query(ctx, inventoryListSelect+` WHERE target_id = $1 ORDER BY version DESC LIMIT $2`, targetID, MaxAPIBASInventoryVersions)
	if err != nil {
		return nil, fmt.Errorf("list apibas inventories: %w", err)
	}
	defer rows.Close()
	var out []APIBASInventory
	for rows.Next() {
		r, err := scanInventory(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// APIBASTargetSummary is a target as the console lists it: what identifies and scopes it, and its newest inventory if any.
// Credential references are deliberately absent.
type APIBASTargetSummary struct {
	ID               string
	Name             string
	BaseURL          string
	Environment      string
	Enabled          bool
	AllowedHosts     []string
	AllowedPaths     []string
	ScenarioCount    int
	CreatedBy        string
	CreatedAt        time.Time
	InventoryVersion int // 0 when the target has no inventory
	InventoryOps     int
	InventoryAt      *time.Time
}

// ListAPIBASTargetSummaries returns up to 200 targets, newest first, each with its newest inventory version.
func ListAPIBASTargetSummaries(ctx context.Context, pool *pgxpool.Pool) ([]APIBASTargetSummary, error) {
	rows, err := pool.Query(ctx, `
		SELECT t.id, t.name, t.base_url, t.environment, t.enabled, t.allowed_hosts::text, t.allowed_paths::text,
		       jsonb_array_length(t.allowed_scenarios), t.created_by, t.created_at,
		       COALESCE(i.version, 0), COALESCE(i.operations, 0), i.imported_at
		  FROM apibas_targets t
		  LEFT JOIN LATERAL (
		        SELECT version, operations, imported_at FROM apibas_target_inventories
		         WHERE target_id = t.id ORDER BY version DESC LIMIT 1) i ON true
		 ORDER BY t.created_at DESC, t.id LIMIT 200`)
	if err != nil {
		return nil, fmt.Errorf("list apibas targets: %w", err)
	}
	defer rows.Close()
	var out []APIBASTargetSummary
	for rows.Next() {
		var s APIBASTargetSummary
		var hosts, paths string
		if err := rows.Scan(&s.ID, &s.Name, &s.BaseURL, &s.Environment, &s.Enabled, &hosts, &paths, &s.ScenarioCount, &s.CreatedBy,
			&s.CreatedAt, &s.InventoryVersion, &s.InventoryOps, &s.InventoryAt); err != nil {
			return nil, fmt.Errorf("read apibas target: %w", err)
		}
		if err := json.Unmarshal([]byte(hosts), &s.AllowedHosts); err != nil {
			return nil, fmt.Errorf("decode allowed hosts: %w", err)
		}
		if err := json.Unmarshal([]byte(paths), &s.AllowedPaths); err != nil {
			return nil, fmt.Errorf("decode allowed paths: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
