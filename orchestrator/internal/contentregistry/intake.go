package contentregistry

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/scenario"
)

// MigrationDone reports whether the one-time migration marker exists.
func (r *Registry) MigrationDone(ctx context.Context) (bool, error) {
	var done bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM content_registry_state)`).Scan(&done)
	return done, err
}

func (r *Registry) versionByHash(ctx context.Context, contentID, sum string) (Version, bool, error) {
	v, err := scanVersion(r.pool.QueryRow(ctx,
		`SELECT `+versionCols+` FROM content_versions WHERE content_id = $1 AND artifact_sha256 = $2`, contentID, sum))
	if errors.Is(err, pgx.ErrNoRows) {
		return Version{}, false, nil
	}
	return v, err == nil, err
}

func (r *Registry) hasVersions(ctx context.Context, contentID string) (bool, error) {
	var ok bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM content_versions WHERE content_id = $1)`, contentID).Scan(&ok)
	return ok, err
}

// otherLocalSource returns the local intake source a custom/intel file must
// not share a content id with, or "" for any other source.
func otherLocalSource(s IntakeSource) IntakeSource {
	switch s {
	case SourceCustom:
		return SourceIntel
	case SourceIntel:
		return SourceCustom
	}
	return ""
}

type queryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// hasVersionsFromSource reports whether contentID has any version taken in
// through the given intake source.
func hasVersionsFromSource(ctx context.Context, q queryRower, contentID string, src IntakeSource) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM content_versions WHERE content_id = $1 AND intake_source = $2)`,
		contentID, string(src)).Scan(&ok)
	return ok, err
}

func (r *Registry) refuse(f scenario.IntakeFile, contentID, reason string) scenario.IntakeDecision {
	r.NoteRefusal(f.Path, contentID, f.Source, reason)
	return scenario.IntakeDecision{Accepted: false, Reason: reason}
}

func (r *Registry) refuseCollision(ctx context.Context, f scenario.IntakeFile, contentID string, attempted Origin) scenario.IntakeDecision {
	r.audit(ctx, "content_registry.collision", contentID,
		map[string]any{"path": f.Path, "attempted_origin": string(attempted)}, "denied")
	return r.refuse(f, contentID, "content id already registered with a different origin")
}

// refuseSourceCollision refuses a custom file claiming an intel id or vice
// versa. Both are LOCAL, so the origin check alone cannot catch it.
func (r *Registry) refuseSourceCollision(ctx context.Context, f scenario.IntakeFile, contentID string) scenario.IntakeDecision {
	r.audit(ctx, "content_registry.collision", contentID,
		map[string]any{"path": f.Path, "attempted_source": f.Source}, "denied")
	return r.refuse(f, contentID, ErrSourceCollision.Error())
}

// Intake applies spec §5.1: origin/trust/lifecycle come from location and
// proof only, never from YAML fields. A returned error means infrastructure
// failure (the caller must treat the file as not executable); a refused
// decision means policy.
func (r *Registry) Intake(ctx context.Context, f scenario.IntakeFile) (scenario.IntakeDecision, error) {
	a, err := analyzeArtifact(f.Artifact)
	if err != nil {
		return r.refuse(f, "", err.Error()), nil
	}

	// Origin is derived from the source first, so an identical-bytes hit under
	// a different origin is a collision, not a no-op accept.
	var targetOrigin Origin
	switch IntakeSource(f.Source) {
	case SourceBuiltin:
		targetOrigin = OriginVendor
	case SourceIntel, SourceCustom:
		targetOrigin = OriginLocal
	default:
		return scenario.IntakeDecision{}, fmt.Errorf("unknown intake source %q", f.Source)
	}

	// A custom file may not take over an intel id (or vice versa), even with
	// identical bytes, so this runs before the hash pre-check. createVersion
	// repeats it under the content lock.
	if other := otherLocalSource(IntakeSource(f.Source)); other != "" {
		clash, err := hasVersionsFromSource(ctx, r.pool, a.contentID, other)
		if err != nil {
			return scenario.IntakeDecision{}, err
		}
		if clash {
			return r.refuseSourceCollision(ctx, f, a.contentID), nil
		}
	}

	if hit, found, err := r.versionByHash(ctx, a.contentID, sha256Hex(f.Artifact)); err != nil {
		return scenario.IntakeDecision{}, err
	} else if found {
		if hit.Origin != targetOrigin {
			return r.refuseCollision(ctx, f, a.contentID, targetOrigin), nil
		}
		return scenario.IntakeDecision{Accepted: true}, nil
	}

	nv := newVersion{contentID: a.contentID, artifact: f.Artifact, analysis: a, actor: ActorIntake,
		source: IntakeSource(f.Source), origin: targetOrigin, exclusiveLocalSource: true}
	switch IntakeSource(f.Source) {
	case SourceBuiltin:
		nv.lifecycle = LifecyclePublished
		switch {
		case f.SignatureVerified && len(f.Signature) > 0:
			nv.trust, nv.signature = TrustVendorSigned, f.Signature
		case r.devBuild():
			nv.trust = TrustUntrusted
		default:
			return r.refuse(f, a.contentID, "builtin signature not verified"), nil
		}
	case SourceIntel:
		nv.trust, nv.lifecycle, nv.actor = TrustUntrusted, LifecycleDraft, ActorGenerator
	case SourceCustom:
		done, err := r.MigrationDone(ctx)
		if err != nil {
			return scenario.IntakeDecision{}, err
		}
		has, err := r.hasVersions(ctx, a.contentID)
		if err != nil {
			return scenario.IntakeDecision{}, err
		}
		if !done && !has {
			nv.trust, nv.lifecycle, nv.actor, nv.reason = TrustLocalTrusted, LifecyclePublishedLocal, ActorMigration, MigrationReason
			nv.grandfatherEligible = true
		} else {
			nv.trust, nv.lifecycle, nv.reason = TrustUntrusted, LifecycleDraft, "changed outside the operator UI"
		}
	}

	if _, _, err := r.createVersion(ctx, nv); err != nil {
		if errors.Is(err, ErrOriginCollision) {
			return r.refuseCollision(ctx, f, a.contentID, nv.origin), nil
		}
		if errors.Is(err, ErrSourceCollision) {
			return r.refuseSourceCollision(ctx, f, a.contentID), nil
		}
		return scenario.IntakeDecision{}, err
	}
	return scenario.IntakeDecision{Accepted: true}, nil
}

// RegisterLocalApproved is the UI save path: an explicit operator action
// that approves exactly these bytes for local execution.
func (r *Registry) RegisterLocalApproved(ctx context.Context, contentID string, artifact []byte, actor string) error {
	if !IsHumanActor(actor) {
		return fmt.Errorf("local approval requires a human actor, got %q", actor)
	}
	a, err := analyzeArtifact(artifact)
	if err != nil {
		return err
	}
	if a.contentID != contentID {
		return fmt.Errorf("artifact id %q does not match %q", a.contentID, contentID)
	}
	v, hit, err := r.versionByHash(ctx, contentID, sha256Hex(artifact))
	if err != nil {
		return err
	}
	if hit {
		return r.approveExisting(ctx, v, actor)
	}
	vid, created, err := r.createVersion(ctx, newVersion{contentID: contentID, origin: OriginLocal, source: SourceCustom,
		artifact: artifact, trust: TrustLocalTrusted, lifecycle: LifecyclePublishedLocal, actor: actor,
		reason: "operator save", analysis: a, exclusiveLocalSource: true})
	if err != nil || created {
		return err
	}
	// Lost a race: a concurrent intake registered these bytes first.
	v, err = r.LoadVersion(ctx, vid)
	if err != nil {
		return err
	}
	return r.approveExisting(ctx, v, actor)
}

// approveExisting applies an operator approval to an already-registered
// version of the same bytes.
func (r *Registry) approveExisting(ctx context.Context, v Version, actor string) error {
	if v.Origin != OriginLocal {
		return ErrOriginCollision
	}
	if v.Lifecycle == LifecyclePublishedLocal {
		return nil
	}
	return r.Transition(ctx, v.ID, LifecyclePublishedLocal, actor, "operator save")
}

// RetireExecutable retires every PUBLISHED / PUBLISHED_LOCAL version.
func (r *Registry) RetireExecutable(ctx context.Context, contentID, actor, reason string) error {
	vs, err := r.ListVersions(ctx, contentID)
	if err != nil {
		return err
	}
	for _, v := range vs {
		if v.Lifecycle == LifecyclePublished || v.Lifecycle == LifecyclePublishedLocal {
			if err := r.Transition(ctx, v.ID, LifecycleRetired, actor, reason); err != nil {
				return err
			}
		}
	}
	return nil
}

// Transition moves one version through the state machine, writing the
// update and its event in one transaction.
func (r *Registry) Transition(ctx context.Context, versionID string, to Lifecycle, actor, reason string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var origin, trust, lc string
	err = tx.QueryRow(ctx, `SELECT origin, trust_level, lifecycle FROM content_versions WHERE id = $1 FOR UPDATE`,
		versionID).Scan(&origin, &trust, &lc)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrVersionNotFound
	}
	if err != nil {
		return err
	}
	if err := CheckTransition(Origin(origin), Trust(trust), Lifecycle(lc), to, actor); err != nil {
		return err
	}
	newTrust := TrustAfter(Origin(origin), Trust(trust), to)
	if _, err := tx.Exec(ctx, `UPDATE content_versions SET lifecycle = $2, trust_level = $3 WHERE id = $1`,
		versionID, string(to), string(newTrust)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO content_version_events (content_version_id, from_lifecycle, to_lifecycle, from_trust, to_trust, actor, reason)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		versionID, lc, string(to), trust, string(newTrust), actor, reason); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
