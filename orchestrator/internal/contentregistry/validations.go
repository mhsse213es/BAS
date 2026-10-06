package contentregistry

import (
	"context"
	"encoding/json"
	"time"
)

// DetectionEffectiveness = (DETECTED+PREVENTED+LOGGED) / (all outcomes except
// NO_DATA, NOT_APPLICABLE and ERROR). ERROR is excluded by controller ruling
// (Task 14 fix round 1): an execution error measures nothing about detection
// (ERROR != FAIL). A zero denominator is NO_DATA -- never 0%.
func DetectionEffectiveness(outcomes []string) (float64, string) {
	var num, den int
	for _, o := range outcomes {
		switch o {
		case "NO_DATA", "NOT_APPLICABLE", "ERROR":
			continue
		case "DETECTED", "PREVENTED", "LOGGED":
			num++
		}
		den++
	}
	if den == 0 {
		return 0, "NO_DATA"
	}
	return float64(num) / float64(den), "OK"
}

type ValidationRow struct {
	Level     string          `json:"level"`
	Outcome   string          `json:"outcome"`
	RunID     *string         `json:"runId,omitempty"`
	Validator string          `json:"validator"`
	Detail    json.RawMessage `json:"detail"`
	CreatedAt time.Time       `json:"createdAt"`
}

type EventRow struct {
	From   *string   `json:"fromLifecycle,omitempty"`
	To     string    `json:"toLifecycle"`
	Trust  string    `json:"toTrust"`
	Actor  string    `json:"actor"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

type SourceRow struct {
	EntityType string     `json:"entityType"`
	EntityID   string     `json:"entityId"`
	Provider   string     `json:"provider"`
	ExternalID string     `json:"externalId"`
	Confidence string     `json:"confidenceAtGeneration"`
	FirstSeen  *time.Time `json:"firstSeenAtGeneration,omitempty"`
	LastSync   *time.Time `json:"lastSyncAtGeneration,omitempty"`
	Role       string     `json:"role"`
}

type VersionDetail struct {
	ID            string          `json:"id"`
	ContentID     string          `json:"contentId"`
	Version       int             `json:"version"`
	Origin        string          `json:"origin"`
	Trust         string          `json:"trust"`
	Lifecycle     string          `json:"lifecycle"`
	SHA256        string          `json:"artifactSha256"`
	Source        string          `json:"intakeSource"`
	CreatedBy     string          `json:"createdBy"`
	CreatedAt     time.Time       `json:"createdAt"`
	Generation    json.RawMessage `json:"generation"`
	Sources       []SourceRow     `json:"sources"`
	Safety        json.RawMessage `json:"safetyVerdicts"`
	Validations   []ValidationRow `json:"validations"`
	Events        []EventRow      `json:"events"`
	DetectionRate *float64        `json:"detectionEffectiveness,omitempty"`
	DetectionStat string          `json:"detectionEffectivenessStatus"`
}

// VersionDetail assembles the audit view of one version. Every sub-query
// error is returned: a half-empty provenance view must not read as "nothing
// recorded".
func (r *Registry) VersionDetail(ctx context.Context, vid string) (VersionDetail, error) {
	v, err := r.LoadVersion(ctx, vid)
	if err != nil {
		return VersionDetail{}, err
	}
	d := VersionDetail{ID: v.ID, ContentID: v.ContentID, Version: v.Number, Origin: string(v.Origin),
		Trust: string(v.Trust), Lifecycle: string(v.Lifecycle), SHA256: v.SHA256, Source: string(v.Source),
		CreatedBy: v.CreatedBy, CreatedAt: v.CreatedAt, Sources: []SourceRow{}, Validations: []ValidationRow{}, Events: []EventRow{}}
	if err := r.pool.QueryRow(ctx, `SELECT generation FROM content_versions WHERE id = $1`, vid).Scan(&d.Generation); err != nil {
		return VersionDetail{}, err
	}
	if err := r.pool.QueryRow(ctx,
		`SELECT COALESCE(json_agg(json_build_object('classifier', classifier, 'classifierVersion', classifier_version,
		   'verdict', verdict, 'detail', detail, 'evaluatedAt', evaluated_at)), '[]') FROM content_safety_verdicts WHERE content_version_id = $1`,
		vid).Scan(&d.Safety); err != nil {
		return VersionDetail{}, err
	}

	rows, err := r.pool.Query(ctx, `SELECT entity_type, entity_id, provider, external_id, confidence_at_generation,
		first_seen_at_generation, last_sync_at_generation, role FROM content_version_sources WHERE content_version_id = $1
		ORDER BY role, provider`, vid)
	if err != nil {
		return VersionDetail{}, err
	}
	for rows.Next() {
		var s SourceRow
		if err := rows.Scan(&s.EntityType, &s.EntityID, &s.Provider, &s.ExternalID, &s.Confidence, &s.FirstSeen, &s.LastSync, &s.Role); err != nil {
			rows.Close()
			return VersionDetail{}, err
		}
		d.Sources = append(d.Sources, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return VersionDetail{}, err
	}

	var detection []string
	rows, err = r.pool.Query(ctx, `SELECT level, outcome, run_id, validator, detail, created_at FROM content_validations
		WHERE content_version_id = $1 ORDER BY created_at`, vid)
	if err != nil {
		return VersionDetail{}, err
	}
	for rows.Next() {
		var vr ValidationRow
		if err := rows.Scan(&vr.Level, &vr.Outcome, &vr.RunID, &vr.Validator, &vr.Detail, &vr.CreatedAt); err != nil {
			rows.Close()
			return VersionDetail{}, err
		}
		d.Validations = append(d.Validations, vr)
		if vr.Level == "DETECTION" {
			detection = append(detection, vr.Outcome)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return VersionDetail{}, err
	}
	if rate, st := DetectionEffectiveness(detection); st == "OK" {
		d.DetectionRate, d.DetectionStat = &rate, st
	} else {
		d.DetectionStat = st
	}

	rows, err = r.pool.Query(ctx, `SELECT from_lifecycle, to_lifecycle, to_trust, actor, reason, at
		FROM content_version_events WHERE content_version_id = $1 ORDER BY at, id`, vid)
	if err != nil {
		return VersionDetail{}, err
	}
	for rows.Next() {
		var e EventRow
		if err := rows.Scan(&e.From, &e.To, &e.Trust, &e.Actor, &e.Reason, &e.At); err != nil {
			rows.Close()
			return VersionDetail{}, err
		}
		d.Events = append(d.Events, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return VersionDetail{}, err
	}
	return d, nil
}

type Summary struct {
	ExecutableVersion   int    `json:"executableVersion"`
	ExecutableLifecycle string `json:"executableLifecycle,omitempty"`
	ExecutableTrust     string `json:"executableTrust,omitempty"`
	LatestVersion       int    `json:"latestVersion"`
	LatestVersionID     string `json:"latestVersionId"`
	LatestLifecycle     string `json:"latestLifecycle"`
	LatestTrust         string `json:"latestTrust"`
}

// Summaries returns one badge summary per content id for list views, in a
// single query. It mirrors the gate's combination rule (without signature
// re-verification, which only the dispatch path pays for).
func (r *Registry) Summaries(ctx context.Context) (map[string]Summary, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, content_id, version, origin, trust_level, lifecycle FROM content_versions ORDER BY content_id, version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Summary{}
	for rows.Next() {
		var id, cid, o, tr, lc string
		var n int
		if err := rows.Scan(&id, &cid, &n, &o, &tr, &lc); err != nil {
			return nil, err
		}
		s, seen := out[cid]
		if !seen {
			s = Summary{LatestVersion: n, LatestVersionID: id, LatestLifecycle: lc, LatestTrust: tr}
		}
		// Same rule as the gate: a dev build cannot verify signatures, so
		// VENDOR_SIGNED content is not executable there.
		if s.ExecutableVersion == 0 && Executable(Origin(o), Trust(tr), Lifecycle(lc), r.devBuild()) &&
			!(r.devBuild() && Trust(tr) == TrustVendorSigned) {
			s.ExecutableVersion, s.ExecutableLifecycle, s.ExecutableTrust = n, lc, tr
		}
		out[cid] = s
	}
	return out, rows.Err()
}
