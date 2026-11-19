package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/models"
)

// Binary revocation (P3). An administrator revokes an agent binary hash from the console. A revoked hash is never
// trusted (not Verified), it does not count as a previous release, and an agent running it is quarantined. A
// revocation is stored in binary_revocations so it takes effect at once; the release also carries the same hashes as
// "#revoked" lines in the signed manifest, and the carry step copies them into every later release.
//
// Revocation is separate from retirement: an old release stays "outdated" until someone revokes it.
// Trust fails closed: if the revocation list cannot be read, the hash is treated as revoked.

var sha256HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// binaryRevokedInDB reports whether the revocation table holds hash.
func (h *Handler) binaryRevokedInDB(ctx context.Context, hash string) (bool, error) {
	var revoked bool
	err := h.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM binary_revocations WHERE sha256 = $1)`, hash).Scan(&revoked)
	return revoked, err
}

// revokedFailClosed reports whether an agent binary hash is revoked, by the signed manifest or the revocation table.
// An empty hash is not revoked. A failed lookup counts as revoked, so an unreadable list never grants trust.
func (h *Handler) revokedFailClosed(ctx context.Context, hash string) bool {
	if hash == "" {
		return false
	}
	if h.manifest != nil && h.manifest.HashRevoked(hash) {
		return true
	}
	revoked, err := h.binaryRevokedInDB(ctx, strings.ToLower(hash))
	if err != nil {
		log.Printf("[!] binary revocation lookup failed for %s...: %v (treated as revoked)", hash[:min(12, len(hash))], err)
		return true
	}
	return revoked
}

// GET /api/agent-binaries/revocations -> {"items": [...]}. Any signed-in user; the console shows which hashes are revoked.
func (h *Handler) ListBinaryRevocations(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT sha256, reason, revoked_by, revoked_at FROM binary_revocations ORDER BY revoked_at DESC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	// source is "console" (stored here, reversible by an admin) or "release" (written into the signed manifest, so only a
	// new signed release can reverse it).
	type item struct {
		SHA256     string `json:"sha256"`
		Reason     string `json:"reason"`
		RevokedBy  string `json:"revokedBy"`
		RevokedAt  string `json:"revokedAt"`
		Source     string `json:"source"`
		Reversible bool   `json:"reversible"`
	}
	items := []item{}
	inRelease := map[string]bool{}
	if h.manifest != nil {
		for _, hash := range h.manifest.RevokedHashes() {
			inRelease[hash] = true
			items = append(items, item{SHA256: hash, Reason: "Revoked in the signed release", RevokedBy: "release", Source: "release"})
		}
	}
	for rows.Next() {
		var it item
		var at time.Time
		if err := rows.Scan(&it.SHA256, &it.Reason, &it.RevokedBy, &at); err != nil {
			continue
		}
		if inRelease[it.SHA256] {
			continue // listed once, as the signed revocation, which is the one that cannot be reversed here
		}
		it.RevokedAt = at.UTC().Format(time.RFC3339)
		it.Source, it.Reversible = "console", true
		items = append(items, it)
	}
	respond(w, map[string]any{"items": items})
}

// DELETE /api/agent-binaries/revocations/{sha256}
// Reverses a revocation made from the console. It lifts the revocation only: agents that were quarantined stay
// quarantined until an operator restores them, and that restore checks trust again. A revocation written into the
// signed release cannot be reversed here; it needs a new signed release. Admin-only (route group).
func (h *Handler) UnrevokeAgentBinary(w http.ResponseWriter, r *http.Request) {
	hash := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "sha256")))
	if !sha256HexPattern.MatchString(hash) {
		jsonError(w, `the hash must be a 64-character hex SHA-256 of an agent binary`, http.StatusBadRequest)
		return
	}
	if h.manifest != nil && h.manifest.HashRevoked(hash) {
		jsonError(w, "this binary is revoked in the signed release, so the console cannot reverse it; only a new signed release can", http.StatusConflict)
		return
	}
	tag, err := h.db.Exec(r.Context(), `DELETE FROM binary_revocations WHERE sha256 = $1`, hash)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "that binary is not revoked", http.StatusNotFound)
		return
	}
	var held int64
	_ = h.db.QueryRow(r.Context(), `SELECT COUNT(*) FROM agents WHERE binary_hash = $1 AND state = 'quarantined'`, hash).Scan(&held)
	h.auditLog(r, "agent_binary.unrevoke", hash, map[string]any{"agents_still_quarantined": held}, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate})
	respond(w, map[string]any{"sha256": hash, "agentsStillQuarantined": held})
}

// POST /api/agent-binaries/revocations   body {"sha256": "<64 hex>", "reason": "..."}
// Revokes the hash and quarantines every agent currently running it. Admin-only (route group).
func (h *Handler) RevokeAgentBinary(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SHA256 string `json:"sha256"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	hash := strings.ToLower(strings.TrimSpace(body.SHA256))
	if !sha256HexPattern.MatchString(hash) {
		jsonError(w, `"sha256" must be a 64-character hex SHA-256 of an agent binary`, http.StatusBadRequest)
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if len(reason) > 500 {
		jsonError(w, `"reason" must be 500 characters or fewer`, http.StatusBadRequest)
		return
	}
	actorID := ""
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		actorID = claims.UserID
	}
	if _, err := h.db.Exec(r.Context(), `
		INSERT INTO binary_revocations (sha256, reason, revoked_by, revoked_at) VALUES ($1, $2, $3, NOW())
		ON CONFLICT (sha256) DO NOTHING`, hash, reason, actorID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Quarantine the agents running it now, rather than on their next heartbeat. Only states that trust can move are
	// changed; an operator quarantine, retirement or restriction is left as it is.
	tag, err := h.db.Exec(r.Context(), `
		UPDATE agents SET state = 'quarantined', binary_trusted = false
		WHERE binary_hash = $1 AND state IN ('active', 'outdated')`, hash)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	quarantined := tag.RowsAffected()
	h.auditLog(r, "agent_binary.revoke", hash, map[string]any{"reason": reason, "agents_quarantined": quarantined}, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate})
	respond(w, map[string]any{"sha256": hash, "agentsQuarantined": quarantined})
}
