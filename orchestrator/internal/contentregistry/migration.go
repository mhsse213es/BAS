package contentregistry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// migrationLockKey is the single global advisory-lock key serializing the
// migration marker against in-flight grandfather intake.
const migrationLockKey int64 = 0x7C0F_4D16_A710_0001

type AffectedRef struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	ScenarioID string `json:"scenarioId"`
}

type Inventory struct {
	IntelDrafted        []string      `json:"intelDrafted"`
	AffectedSchedules   []AffectedRef `json:"affectedSchedules"`
	AffectedCampaigns   []AffectedRef `json:"affectedCampaigns"`
	CustomGrandfathered []string      `json:"customGrandfathered"`
	BuiltinRefused      []Refusal     `json:"builtinRefused"`
	MigratedAt          time.Time     `json:"migratedAt"`
}

// blockedSet returns the subset of ids that have no executable version right
// now. It uses ResolveExecutable, the same resolution as the execution gate,
// so retired, rejected, untrusted, unregistered and tampered content all count
// as blocked. A registry/DB failure is an error, never "not blocked".
func (r *Registry) blockedSet(ctx context.Context, ids []string) (map[string]bool, error) {
	blocked := map[string]bool{}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		_, err := r.resolveExecutable(ctx, id, false)
		if err == nil {
			continue
		}
		var ne *ErrNotExecutable
		if errors.As(err, &ne) {
			blocked[id] = true
			continue
		}
		return nil, err
	}
	return blocked, nil
}

// nonExecutableIntel lists intel content ids with no executable version.
func (r *Registry) nonExecutableIntel(ctx context.Context) ([]string, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT DISTINCT content_id FROM content_versions WHERE intake_source = 'intel' ORDER BY content_id`)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	blocked, err := r.blockedSet(ctx, ids)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, id := range ids {
		if blocked[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

// enabledSchedules returns enabled scheduled assessments. Name carries the
// schedule type because job_schedules has no name column.
func (r *Registry) enabledSchedules(ctx context.Context) ([]AffectedRef, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, type, COALESCE(payload->>'scenarioId', '') FROM job_schedules
		  WHERE type = 'scheduled_assessment' AND enabled ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (AffectedRef, error) {
		var a AffectedRef
		err := row.Scan(&a.ID, &a.Name, &a.ScenarioID)
		return a, err
	})
}

func filterRefs(refs []AffectedRef, keep map[string]bool) []AffectedRef {
	var out []AffectedRef
	for _, a := range refs {
		if keep[a.ScenarioID] {
			out = append(out, a)
		}
	}
	return out
}

// BlockedSchedules is the live banner query: enabled scheduled assessments
// whose scenario has no executable version right now (resolved through the
// execution gate, so retired or non-executable versions do not count as OK).
func (r *Registry) BlockedSchedules(ctx context.Context) ([]AffectedRef, error) {
	refs, err := r.enabledSchedules(ctx)
	if err != nil || len(refs) == 0 {
		return nil, err
	}
	ids := make([]string, 0, len(refs))
	for _, a := range refs {
		ids = append(ids, a.ScenarioID)
	}
	blocked, err := r.blockedSet(ctx, ids)
	if err != nil {
		return nil, err
	}
	return filterRefs(refs, blocked), nil
}

// CompleteMigration computes and stores the inventory once, then sets the
// marker that ends custom-file grandfathering. Idempotent and safe under
// concurrent boots: the marker is INSERT ... ON CONFLICT DO NOTHING, so exactly
// one caller sees firstTime=true; others return the stored inventory.
func (r *Registry) CompleteMigration(ctx context.Context) (Inventory, bool, error) {
	// Cheap pre-check outside any lock: the common boot after the first one.
	if inv, ok, err := r.MigrationInventory(ctx); err != nil || ok {
		return inv, false, err
	}
	// Exclusive lock: waits for in-flight grandfather intakes (shared lock) to
	// commit, and holds new ones off until the marker commits, so no intake can
	// grandfather after the inventory is computed.
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Inventory{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLockKey); err != nil {
		return Inventory{}, false, err
	}
	// Re-check under the lock: another instance may have finished meanwhile.
	if inv, ok, err := r.migrationInventory(ctx, tx); err != nil || ok {
		return inv, false, err
	}
	inv, err := r.computeInventory(ctx)
	if err != nil {
		return inv, false, err
	}
	b, err := json.Marshal(inv)
	if err != nil {
		return inv, false, fmt.Errorf("marshal inventory: %w", err)
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO content_registry_state (id, migrated_at, inventory) VALUES (1, $1, $2) ON CONFLICT (id) DO NOTHING`,
		inv.MigratedAt, b)
	if err != nil {
		return inv, false, err
	}
	if tag.RowsAffected() == 0 {
		stored, _, err := r.migrationInventory(ctx, tx)
		return stored, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return inv, false, err
	}
	r.audit(ctx, "content_registry.migration_inventory", "content_registry", map[string]any{
		"intel_drafted": len(inv.IntelDrafted), "affected_schedules": len(inv.AffectedSchedules),
		"affected_campaigns": len(inv.AffectedCampaigns), "custom_grandfathered": len(inv.CustomGrandfathered),
		"builtin_refused": len(inv.BuiltinRefused)}, "ok")
	return inv, true, nil
}

// computeInventory runs while the exclusive migration lock is held.
func (r *Registry) computeInventory(ctx context.Context) (Inventory, error) {
	var inv Inventory
	var err error
	if inv.IntelDrafted, err = r.nonExecutableIntel(ctx); err != nil {
		return inv, err
	}
	drafted := map[string]bool{}
	for _, id := range inv.IntelDrafted {
		drafted[id] = true
	}
	scheds, err := r.enabledSchedules(ctx)
	if err != nil {
		return inv, err
	}
	inv.AffectedSchedules = filterRefs(scheds, drafted)
	crow, err := r.pool.Query(ctx, `SELECT id, name, scenario_id FROM campaigns WHERE scenario_id = ANY($1) ORDER BY id`, inv.IntelDrafted)
	if err != nil {
		return inv, err
	}
	if inv.AffectedCampaigns, err = pgx.CollectRows(crow, func(row pgx.CollectableRow) (AffectedRef, error) {
		var a AffectedRef
		err := row.Scan(&a.ID, &a.Name, &a.ScenarioID)
		return a, err
	}); err != nil {
		return inv, err
	}
	grow, err := r.pool.Query(ctx,
		`SELECT DISTINCT cv.content_id FROM content_version_events e JOIN content_versions cv ON cv.id = e.content_version_id
		  WHERE e.actor = $1 ORDER BY cv.content_id`, ActorMigration)
	if err != nil {
		return inv, err
	}
	if inv.CustomGrandfathered, err = pgx.CollectRows(grow, pgx.RowTo[string]); err != nil {
		return inv, err
	}
	inv.BuiltinRefused = r.Refusals()
	inv.MigratedAt = time.Now().UTC().Truncate(time.Microsecond)
	return inv, nil
}

func (r *Registry) MigrationInventory(ctx context.Context) (Inventory, bool, error) {
	return r.migrationInventory(ctx, r.pool)
}

func (r *Registry) migrationInventory(ctx context.Context, q queryRower) (Inventory, bool, error) {
	var raw []byte
	var at time.Time
	err := q.QueryRow(ctx, `SELECT migrated_at, inventory FROM content_registry_state WHERE id = 1`).Scan(&at, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return Inventory{}, false, nil
	}
	if err != nil {
		return Inventory{}, false, err
	}
	var inv Inventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		return Inventory{}, false, fmt.Errorf("stored migration inventory unreadable: %w", err)
	}
	inv.MigratedAt = at.UTC()
	return inv, true, nil
}
