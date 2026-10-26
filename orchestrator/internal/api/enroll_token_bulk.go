package api

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/audspect/bas/internal/auth"
)

const bulkTokenMax = 500

// POST /api/enrollment-tokens/bulk -- one token per hostname for a rollout, in a single all-or-nothing
// request. ?format=csv returns hostname,agentId,token,expiresAt for handing out. Tokens are shown once.
// Hostnames must be given exactly as the operating system reports them (the agent's ID is derived
// from that spelling); exact duplicates are collapsed and reported. Admin-only.
func (h *Handler) BulkCreateEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Hostnames []string `json:"hostnames"`
		TTLHours  *int     `json:"ttlHours"`
		Note      string   `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if len(body.Hostnames) == 0 || len(body.Hostnames) > bulkTokenMax {
		jsonError(w, "give between 1 and 500 hostnames", http.StatusBadRequest)
		return
	}
	ttl := enrollTokenDefaultTTL
	if body.TTLHours != nil {
		ttl = time.Duration(*body.TTLHours) * time.Hour
		if ttl <= 0 || ttl > enrollTokenMaxTTL {
			jsonError(w, "ttlHours must be between 1 and 168", http.StatusBadRequest)
			return
		}
	}
	note := strings.TrimSpace(body.Note)
	if len(note) > 200 {
		note = note[:200]
	}

	seen := map[string]bool{}
	hosts := make([]string, 0, len(body.Hostnames))
	duplicates := []string{}
	for _, hn := range body.Hostnames {
		if strings.TrimSpace(hn) == "" || len(hn) > 255 {
			jsonError(w, "every hostname must be non-empty and at most 255 characters", http.StatusBadRequest)
			return
		}
		if seen[hn] {
			duplicates = append(duplicates, hn)
			continue
		}
		seen[hn] = true
		hosts = append(hosts, hn)
	}

	createdBy := ""
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		createdBy = claims.UserID
	}
	ctx := r.Context()
	tx, err := h.db.Begin(ctx)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	type issued struct {
		Hostname  string    `json:"hostname"`
		AgentID   string    `json:"agentId"`
		Token     string    `json:"token"`
		ID        string    `json:"id"`
		ExpiresAt time.Time `json:"expiresAt"`
	}
	out := make([]issued, 0, len(hosts))
	agentIDs := make([]string, 0, len(hosts))
	for _, hn := range hosts {
		token, err := newEnrollmentToken()
		if err != nil {
			jsonError(w, "could not generate a token", http.StatusInternalServerError)
			return
		}
		agentID := agentIDForHostname(hn)
		var id string
		var expires time.Time
		if err := tx.QueryRow(ctx, `
			INSERT INTO agent_enrollment_tokens (token_hash, agent_id, note, created_by, expires_at)
			VALUES ($1, $2, $3, $4, NOW() + make_interval(secs => $5))
			RETURNING id, expires_at`,
			hashEnrollmentToken(token), agentID, note, createdBy, ttl.Seconds()).Scan(&id, &expires); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out = append(out, issued{Hostname: hn, AgentID: agentID, Token: token, ID: id, ExpiresAt: expires})
		agentIDs = append(agentIDs, agentID)
	}
	if err := tx.Commit(ctx); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "enrollment_token.bulk_create", "bulk",
		map[string]any{"count": len(out), "note": note, "agentIds": agentIDs}, "ok")

	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Query().Get("format") == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="enrollment-tokens.csv"`)
		cw := csv.NewWriter(w)
		cw.Write([]string{"hostname", "agentId", "token", "expiresAt"})
		for _, t := range out {
			cw.Write([]string{csvSafe(t.Hostname), t.AgentID, t.Token, t.ExpiresAt.UTC().Format(time.RFC3339)})
		}
		cw.Flush()
		return
	}
	respond(w, map[string]any{"tokens": out, "duplicates": duplicates})
}

// csvSafe stops a hostname from being read as a spreadsheet formula when the file is opened in Excel.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}
