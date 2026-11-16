package api

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/models"
)

// Minimum supported agent version (P2). It is a fleet-wide setting with NO default floor: until an administrator
// sets one, no agent is below it. An agent below the minimum is shown as below minimum with an upgrade warning, and
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

// minimumAgentVersion returns the fleet minimum agent version, or "" when none is set.
func (h *Handler) minimumAgentVersion(ctx context.Context) string {
	var v string
	if err := h.db.QueryRow(ctx,
		`SELECT COALESCE((SELECT value->>'version' FROM fleet_settings WHERE key = $1), '')`,
		fleetMinAgentVersionKey).Scan(&v); err != nil {
		return ""
	}
	return v
}

// GET /api/fleet/min-agent-version -> {"version": "1.9.7"}; "" means no minimum is set. Any signed-in user.
func (h *Handler) GetFleetMinAgentVersion(w http.ResponseWriter, r *http.Request) {
	respond(w, map[string]any{"version": h.minimumAgentVersion(r.Context())})
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
	respond(w, map[string]any{"version": version})
}
