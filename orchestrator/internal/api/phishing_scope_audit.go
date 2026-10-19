package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/phishscope"
)

// ActionPhishingScopeRecorded is the audit action for an identity allowlist
// record. One row is written whenever the configured allowlist differs from the
// last recorded one.
const ActionPhishingScopeRecorded = "phishing.identity_scope.recorded"

// RecordPhishingScopeAtStartup records the installation's identity allowlist to
// the audit log. The orchestrator reads the allowlist from its container
// environment, which changes only when the container is recreated. So this runs
// at startup, and a row is written only when the fingerprint differs from the
// last recorded one. An unchanged restart adds no row.
//
// The record holds the client IDs and a SHA-256 per user entry. It never holds a
// user principal name or the raw text of a malformed value, since a bad entry
// may be a real name. A malformed allowlist is recorded as an error outcome.
// The write is synchronous, so a failed write is returned rather than lost.
func (h *Handler) RecordPhishingScopeAtStartup(ctx context.Context) error {
	scope, parseErr := phishscope.ParseScope(
		os.Getenv(EnvPhishIdentityTargetUsers), os.Getenv(EnvPhishOAuthSPObjectIDs))

	var fingerprint string
	var detail map[string]any
	outcome := "ok"
	if parseErr != nil {
		outcome = "error"
		fingerprint = "malformed"
		detail = map[string]any{"status": "malformed", "fingerprint": fingerprint}
	} else {
		d := phishscope.Digest(scope)
		fingerprint = d.Fingerprint
		status := "configured"
		if !scope.ConfiguredUsers() && !scope.ConfiguredClients() {
			status = "unconfigured"
		}
		detail = map[string]any{
			"status":      status,
			"fingerprint": fingerprint,
			"userCount":   len(d.UserHashes),
			"userHashes":  d.UserHashes,
			"clientIds":   d.ClientIDs,
		}
	}

	// The fingerprint covers the declared Graph permissions too, so a change to
	// what the scenarios may request is recorded alongside an allowlist change.
	combined := sha256.Sum256([]byte(fingerprint + "|" + phishingGraphPermissionsFingerprint()))
	fingerprint = hex.EncodeToString(combined[:])
	detail["fingerprint"] = fingerprint
	detail["graphPermissions"] = phishingGraphPermissions

	var previous string
	err := h.db.QueryRow(ctx,
		`SELECT detail->>'fingerprint' FROM audit_logs WHERE action = $1 ORDER BY ts DESC, id DESC LIMIT 1`,
		ActionPhishingScopeRecorded).Scan(&previous)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("phishing scope audit: reading last record: %w", err)
	}
	if previous == fingerprint && err == nil {
		return nil // unchanged since the last record
	}
	if errors.Is(err, pgx.ErrNoRows) {
		previous = "none"
	}
	detail["previous"] = previous

	_, err = h.db.Exec(ctx,
		`INSERT INTO audit_logs (actor_id, action, resource, detail, ip, outcome)
		 VALUES ('', $1, 'phishing-identity-scope', $2, 'startup', $3)`,
		ActionPhishingScopeRecorded, detail, outcome)
	if err != nil {
		return fmt.Errorf("phishing scope audit: writing record: %w", err)
	}
	return nil
}
