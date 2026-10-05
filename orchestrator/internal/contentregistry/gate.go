package contentregistry

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/scenario"
)

var _ scenario.ContentRegistry = (*Registry)(nil)

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ResolveExecutable is the single authoritative execution boundary (spec
// §6.1): the highest version passing the gate, parsed from stored bytes.
// VENDOR_SIGNED versions are re-verified on every resolution; a failure
// denies (it never falls through to an older version) and audits a tamper.
func (r *Registry) ResolveExecutable(ctx context.Context, contentID string) (scenario.ExecutableVersion, error) {
	versions, err := r.ListVersions(ctx, contentID)
	if err != nil {
		return scenario.ExecutableVersion{}, fmt.Errorf("content registry unavailable: %w", err)
	}
	if len(versions) == 0 {
		return scenario.ExecutableVersion{}, &ErrNotExecutable{ContentID: contentID, Reason: "not registered"}
	}
	for _, v := range versions {
		if !Executable(v.Origin, v.Trust, v.Lifecycle, r.devBuild()) {
			continue
		}
		if v.Trust == TrustVendorSigned {
			if !r.verifier.SigningEnabled() {
				// A dev build cannot verify signatures: deny, but this is not tampering.
				r.audit(ctx, "content_registry.signing_unavailable", v.ID, map[string]any{
					"content_id": contentID, "version": v.Number}, "denied")
				return scenario.ExecutableVersion{}, &ErrNotExecutable{ContentID: contentID,
					Reason: fmt.Sprintf("v%d is vendor-signed but this build cannot verify signatures", v.Number)}
			}
			ok, verr := r.verifier.Verify(v.Artifact, v.Signature)
			if !ok || verr != nil {
				r.audit(ctx, "content_registry.tamper", v.ID, map[string]any{
					"content_id": contentID, "version": v.Number, "error": errString(verr)}, "denied")
				return scenario.ExecutableVersion{}, &ErrNotExecutable{ContentID: contentID,
					Reason: fmt.Sprintf("signature re-verification failed for v%d", v.Number)}
			}
		}
		sc, perr := v.Parse()
		if perr != nil {
			return scenario.ExecutableVersion{}, &ErrNotExecutable{ContentID: contentID,
				Reason: fmt.Sprintf("v%d artifact unreadable: %v", v.Number, perr)}
		}
		if sc.ID != contentID {
			// Stops validly signed bytes of another content id being swapped into this row.
			return scenario.ExecutableVersion{}, &ErrNotExecutable{ContentID: contentID,
				Reason: fmt.Sprintf("v%d artifact id %q does not match content id", v.Number, sc.ID)}
		}
		return scenario.ExecutableVersion{VersionID: v.ID, ContentID: v.ContentID, Version: v.Number,
			Origin: string(v.Origin), Trust: string(v.Trust), Lifecycle: string(v.Lifecycle), Scenario: sc}, nil
	}
	l := versions[0]
	return scenario.ExecutableVersion{}, &ErrNotExecutable{ContentID: contentID,
		Reason: fmt.Sprintf("no executable version; latest v%d is %s/%s", l.Number, l.Lifecycle, l.Trust)}
}

// AttachVendorSignature is the ONLY writer of signature_bytes and the only
// non-declarative registry invariant (spec §4.2): NULL-only, VENDOR-only,
// verified against the immutable stored bytes, trust set atomically.
func (r *Registry) AttachVendorSignature(ctx context.Context, versionID string, sig []byte, actor string) error {
	if !IsHumanActor(actor) {
		return fmt.Errorf("signature attachment requires a human actor")
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var origin, trust, lc string
	var art, existing []byte
	err = tx.QueryRow(ctx,
		`SELECT origin, trust_level, lifecycle, artifact_bytes, signature_bytes FROM content_versions WHERE id = $1 FOR UPDATE`,
		versionID).Scan(&origin, &trust, &lc, &art, &existing)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrVersionNotFound
	}
	if err != nil {
		return err
	}
	if Origin(origin) != OriginVendor {
		return fmt.Errorf("only VENDOR content can carry a vendor signature")
	}
	if existing != nil {
		return fmt.Errorf("signature already attached")
	}
	ok, verr := r.verifier.Verify(art, sig)
	if verr != nil {
		return fmt.Errorf("signature does not verify against stored artifact: %w", verr)
	}
	if !ok {
		return fmt.Errorf("signature does not verify against stored artifact")
	}
	if _, err := tx.Exec(ctx, `UPDATE content_versions SET signature_bytes = $2, trust_level = 'VENDOR_SIGNED' WHERE id = $1`,
		versionID, sig); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO content_version_events (content_version_id, from_lifecycle, to_lifecycle, from_trust, to_trust, actor, reason)
		 VALUES ($1, $2, $2, $3, 'VENDOR_SIGNED', $4, 'vendor signature attached')`,
		versionID, lc, trust, actor); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
