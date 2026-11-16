package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/models"
)

// Minimum supported agent version (P2). It is a fleet-wide setting. Until an administrator sets one it defaults to the
// previous release (the "#prev-version" line in the signed manifest), so only agents older than the release before this
// one are flagged; an administrator's setting, including "no minimum", always wins. An agent below the minimum is shown as below minimum with an upgrade warning, and
// it keeps running. Blocking execution is a separate, later decision (revocation, P3). This setting does not touch
// trust: an agent's Verified / Outdated / Unverified state still comes from binary_hash against the signed manifest.

// fleetMinAgentVersionKey is the fleet_settings row holding {"version": "1.9.7"}. An empty version means no floor.
const fleetMinAgentVersionKey = "min_agent_version"

var agentVersionPattern = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){0,3}$`)

// parseAgentVersion reads a leading dotted-number version such as "1.9.7" or "v1.9.7-rc1". The suffix after "-" or "+"
// is ignored. ok is false when the version has no usable numeric form.
func parseAgentVersion(s string) (parts []int, ok bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return nil, false
	}
	for _, p := range strings.Split(s, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		parts = append(parts, n)
	}
	return parts, true
}

// belowMinimumAgentVersion reports whether agentVersion is lower than minVersion. It is false when no minimum is set,
// and false when either version cannot be read: an unknown version is reported as unknown, never as below minimum.
func belowMinimumAgentVersion(agentVersion, minVersion string) bool {
	if strings.TrimSpace(minVersion) == "" {
		return false
	}
	a, okA := parseAgentVersion(agentVersion)
	m, okM := parseAgentVersion(minVersion)
	if !okA || !okM {
		return false
	}
	for i := 0; i < len(a) || i < len(m); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(m) {
			y = m[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// previousReleaseVersion is the version of the release before this one, from the signed manifest, or "".
func (h *Handler) previousReleaseVersion() string {
	if h.manifest == nil {
		return ""
	}
	return h.manifest.PreviousReleaseVersion()
}

// effectiveMinimumAgentVersion resolves the fleet minimum and where it came from:
//
//	"setting"          an administrator set it, including setting it to "" (no minimum). The setting always wins.
//	"previous-release" no setting exists, so the minimum is the release before this one (from the signed manifest).
//	"none"             no setting, and the manifest does not name the previous release.
func (h *Handler) effectiveMinimumAgentVersion(ctx context.Context) (version, source string) {
	var v string
	err := h.db.QueryRow(ctx, `SELECT COALESCE(value->>'version', '') FROM fleet_settings WHERE key = $1`, fleetMinAgentVersionKey).Scan(&v)
	if err == nil {
		return v, "setting"
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", "none" // an unreadable setting flags nothing; the minimum never blocks an agent
	}
	if pv := h.previousReleaseVersion(); pv != "" {
		return pv, "previous-release"
	}
	return "", "none"
}

// minimumAgentVersion returns the fleet minimum agent version in force, or "" when none is.
func (h *Handler) minimumAgentVersion(ctx context.Context) string {
	v, _ := h.effectiveMinimumAgentVersion(ctx)
	return v
}

// GET /api/fleet/min-agent-version -> {"version": "1.9.9.3", "source": "previous-release", "default": "1.9.9.3"}.
// "" means no minimum. "default" is what the setting falls back to when it is removed. Any signed-in user.
func (h *Handler) GetFleetMinAgentVersion(w http.ResponseWriter, r *http.Request) {
	v, source := h.effectiveMinimumAgentVersion(r.Context())
	respond(w, map[string]any{"version": v, "source": source, "default": h.previousReleaseVersion()})
}

// DELETE /api/fleet/min-agent-version removes the setting, so the minimum goes back to the previous release.
// Admin-only (route group).
func (h *Handler) ResetFleetMinAgentVersion(w http.ResponseWriter, r *http.Request) {
	if _, err := h.db.Exec(r.Context(), `DELETE FROM fleet_settings WHERE key = $1`, fleetMinAgentVersionKey); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "fleet.min_agent_version_reset", "fleet", map[string]any{"default": h.previousReleaseVersion()}, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate})
	v, source := h.effectiveMinimumAgentVersion(r.Context())
	respond(w, map[string]any{"version": v, "source": source, "default": h.previousReleaseVersion()})
}

// PUT /api/fleet/min-agent-version   body {"version": "1.9.7"}   ("" clears the minimum). Admin-only (route group).
func (h *Handler) SetFleetMinAgentVersion(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Version *string `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Version == nil {
		jsonError(w, `"version" is required: a version such as "1.9.7", or "" to clear`, http.StatusBadRequest)
		return
	}
	version := strings.TrimPrefix(strings.TrimSpace(*body.Version), "v")
	if version != "" && !agentVersionPattern.MatchString(*body.Version) {
		jsonError(w, `"version" must be a dotted number such as "1.9.7", or "" to clear`, http.StatusBadRequest)
		return
	}
	actorID := ""
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		actorID = claims.UserID
	}
	value, _ := json.Marshal(map[string]string{"version": version})
	if _, err := h.db.Exec(r.Context(), `
		INSERT INTO fleet_settings (key, value, updated_by, updated_at) VALUES ($1, $2, $3, NOW())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		fleetMinAgentVersionKey, value, actorID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "fleet.min_agent_version", "fleet", map[string]any{"version": version}, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate})
	respond(w, map[string]any{"version": version, "source": "setting", "default": h.previousReleaseVersion()})
}
