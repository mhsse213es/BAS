package contentregistry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/scenario"
)

// Version is one immutable content version.
type Version struct {
	ID        string
	ContentID string
	Origin    Origin
	Number    int
	SHA256    string
	Artifact  []byte
	Signature []byte
	Trust     Trust
	Lifecycle Lifecycle
	Source    IntakeSource
	CreatedBy string
	CreatedAt time.Time
}

// Parse decodes the stored bytes -- never the disk file.
func (v Version) Parse() (*scenario.Scenario, error) {
	var sc scenario.Scenario
	if err := yaml.Unmarshal(v.Artifact, &sc); err != nil {
		return nil, fmt.Errorf("parse stored v%d of %s: %w", v.Number, v.ContentID, err)
	}
	sc.Source = string(v.Source)
	return &sc, nil
}

const versionCols = `id, content_id, origin, version, artifact_sha256, artifact_bytes, signature_bytes,
	trust_level, lifecycle, intake_source, created_by, created_at`

func scanVersion(row pgx.Row) (Version, error) {
	var v Version
	var origin, trust, lc, src string
	err := row.Scan(&v.ID, &v.ContentID, &origin, &v.Number, &v.SHA256, &v.Artifact, &v.Signature,
		&trust, &lc, &src, &v.CreatedBy, &v.CreatedAt)
	v.Origin, v.Trust, v.Lifecycle, v.Source = Origin(origin), Trust(trust), Lifecycle(lc), IntakeSource(src)
	return v, err
}

func (r *Registry) LoadVersion(ctx context.Context, id string) (Version, error) {
	v, err := scanVersion(r.pool.QueryRow(ctx, `SELECT `+versionCols+` FROM content_versions WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Version{}, ErrVersionNotFound
	}
	return v, err
}

// ListVersions returns every version of contentID, newest first.
func (r *Registry) ListVersions(ctx context.Context, contentID string) ([]Version, error) {
	return listVersions(ctx, r.pool, contentID)
}

// querier is satisfied by *pgxpool.Pool and pgx.Tx, so read helpers can run
// on a caller's transaction without taking another pool connection.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func listVersions(ctx context.Context, q querier, contentID string) ([]Version, error) {
	rows, err := q.Query(ctx,
		`SELECT `+versionCols+` FROM content_versions WHERE content_id = $1 ORDER BY version DESC`, contentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

type sourceSnapshot struct {
	ref        SourceRef
	confidence string
	firstSeen  *time.Time
	lastSync   *time.Time
}

type newVersion struct {
	contentID     string
	origin        Origin
	source        IntakeSource
	artifact      []byte
	signature     []byte
	trust         Trust
	lifecycle     Lifecycle
	actor         string
	reason        string
	analysis      *analysis
	generation    map[string]any
	generationKey string
	sources       []sourceSnapshot
	// grandfatherEligible marks a pre-migration custom file whose trusted
	// values were chosen from an unlocked read; createVersion re-checks it
	// under the content lock and downgrades to DRAFT if no longer eligible.
	grandfatherEligible bool
	// exclusiveLocalSource (set by Intake, RegisterLocalApproved and
	// RegisterGenerated) refuses a custom version when the
	// id already has intel versions and vice versa, re-checked under the lock.
	exclusiveLocalSource bool
}

// createVersion inserts identity (if new), version, creation event,
// STRUCTURAL validation, safety verdict and source snapshots in ONE
// transaction. Identical bytes for the same content id return the existing
// version with created=false. Per-content advisory lock serializes
// concurrent intakes (Review Focus 2).
func (r *Registry) createVersion(ctx context.Context, nv newVersion) (string, bool, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if nv.analysis == nil || nv.contentID != nv.analysis.contentID {
		return "", false, errors.New("content id does not match analyzed artifact")
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, nv.contentID); err != nil {
		return "", false, err
	}
	if other := otherLocalSource(nv.source); nv.exclusiveLocalSource && other != "" {
		clash, err := hasVersionsFromSource(ctx, tx, nv.contentID, other)
		if err != nil {
			return "", false, err
		}
		if clash {
			return "", false, ErrSourceCollision
		}
	}
	sum := sha256Hex(nv.artifact)
	var existing string
	err = tx.QueryRow(ctx, `SELECT id FROM content_versions WHERE content_id = $1 AND artifact_sha256 = $2`,
		nv.contentID, sum).Scan(&existing)
	if err == nil {
		var existingOrigin string
		if err := tx.QueryRow(ctx, `SELECT origin FROM scenarios WHERE scenario_id = $1`, nv.contentID).Scan(&existingOrigin); err != nil {
			return "", false, err
		}
		if Origin(existingOrigin) != nv.origin {
			return "", false, ErrOriginCollision
		}
		return existing, false, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", false, err
	}

	if nv.grandfatherEligible {
		// Shared: many grandfather intakes may run together, but never while
		// CompleteMigration (exclusive) is computing the inventory and setting
		// the marker. Held until this transaction ends.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared($1)`, migrationLockKey); err != nil {
			return "", false, err
		}
		var stillEligible bool
		if err := tx.QueryRow(ctx,
			`SELECT NOT EXISTS (SELECT 1 FROM content_registry_state)
			    AND NOT EXISTS (SELECT 1 FROM content_versions WHERE content_id = $1)`, nv.contentID).Scan(&stillEligible); err != nil {
			return "", false, err
		}
		if !stillEligible {
			nv.trust, nv.lifecycle, nv.actor, nv.reason = TrustUntrusted, LifecycleDraft, ActorIntake, "changed outside the operator UI"
		}
	}

	var origin string
	err = tx.QueryRow(ctx, `SELECT origin FROM scenarios WHERE scenario_id = $1`, nv.contentID).Scan(&origin)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		_, err = tx.Exec(ctx,
			`INSERT INTO scenarios (scenario_id, name, category, origin, generation_key) VALUES ($1, $2, '', $3, NULLIF($4, ''))`,
			nv.contentID, nv.analysis.sc.Name, string(nv.origin), nv.generationKey)
	case err != nil:
		return "", false, err
	case Origin(origin) != nv.origin:
		return "", false, ErrOriginCollision
	default:
		_, err = tx.Exec(ctx,
			`UPDATE scenarios SET name = $2, updated_at = NOW(), generation_key = COALESCE(NULLIF($3, ''), generation_key) WHERE scenario_id = $1`,
			nv.contentID, nv.analysis.sc.Name, nv.generationKey)
	}
	if err != nil {
		return "", false, err
	}

	var next int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) + 1 FROM content_versions WHERE content_id = $1`,
		nv.contentID).Scan(&next); err != nil {
		return "", false, err
	}
	gen := map[string]any{}
	for k, v := range nv.generation {
		gen[k] = v
	}
	if nv.analysis.dynamicScope != "" {
		gen["dynamic_scope"] = nv.analysis.dynamicScope
	}
	if len(nv.analysis.dynamicModes) > 0 {
		gen["dynamic_modes"] = nv.analysis.dynamicModes
	}
	genJSON, _ := json.Marshal(gen)

	var vid string
	if err := tx.QueryRow(ctx,
		`INSERT INTO content_versions (content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes,
		   signature_bytes, trust_level, lifecycle, intake_source, schema_version, technique_ids, supported_os,
		   generation, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id`,
		nv.contentID, string(nv.origin), next, sum, len(nv.artifact), nv.artifact, nv.signature,
		string(nv.trust), string(nv.lifecycle), string(nv.source), schemaVersion, nv.analysis.techniqueIDs,
		nonNil(nv.analysis.supportedOS), genJSON, nv.actor).Scan(&vid); err != nil {
		return "", false, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO content_version_events (content_version_id, from_lifecycle, to_lifecycle, from_trust, to_trust, actor, reason)
		 VALUES ($1, NULL, $2, NULL, $3, $4, $5)`,
		vid, string(nv.lifecycle), string(nv.trust), nv.actor, nv.reason); err != nil {
		return "", false, err
	}

	structural := nv.analysis.structural
	if err := checkTechniqueCatalog(ctx, tx, nv.analysis.techniqueIDs, &structural); err != nil {
		return "", false, err
	}
	sdetail, _ := json.Marshal(structural.detail)
	if _, err := tx.Exec(ctx,
		`INSERT INTO content_validations (content_version_id, level, outcome, validator, validator_version, detail)
		 VALUES ($1, 'STRUCTURAL', $2, $3, $4, $5)`,
		vid, structural.outcome, structuralValidator, structuralValidatorVersion, sdetail); err != nil {
		return "", false, err
	}
	safety, _ := json.Marshal(nv.analysis.safety.detail)
	if _, err := tx.Exec(ctx,
		`INSERT INTO content_safety_verdicts (content_version_id, classifier, classifier_version, verdict, detail)
		 VALUES ($1, $2, $3, $4, $5)`,
		vid, safetyClassifier, safetyClassifierVersion, nv.analysis.safety.verdict, safety); err != nil {
		return "", false, err
	}
	for _, s := range nv.sources {
		if _, err := tx.Exec(ctx,
			`INSERT INTO content_version_sources (content_version_id, entity_type, entity_id, provider, external_id,
			   confidence_at_generation, first_seen_at_generation, last_sync_at_generation, role)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
			vid, s.ref.EntityType, s.ref.EntityID, s.ref.Provider, s.ref.ExternalID, s.confidence,
			s.firstSeen, s.lastSync, s.ref.Role); err != nil {
			return "", false, err
		}
	}
	return vid, true, tx.Commit(ctx)
}

// checkTechniqueCatalog upgrades the structural check with an existence
// lookup when the ATT&CK catalog is populated; an empty catalog is recorded
// as "not checked", never as a pass or fail of the lookup.
func checkTechniqueCatalog(ctx context.Context, tx pgx.Tx, ids []string, res *checkResult) error {
	if len(ids) == 0 {
		return nil
	}
	var catalog int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM techniques`).Scan(&catalog); err != nil {
		return err
	}
	if catalog == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT technique_id FROM techniques WHERE technique_id = ANY($1)`, ids)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		known[id] = true
	}
	rows.Close()
	problems, _ := res.detail["problems"].([]string)
	for _, id := range ids {
		if !known[id] {
			problems = append(problems, "unknown technique id "+id)
		}
	}
	res.detail["problems"] = problems
	res.detail["technique_ids_checked_against_catalog"] = true
	if len(problems) > 0 {
		res.outcome = "FAIL"
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
