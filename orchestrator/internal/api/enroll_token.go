package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
)

// Enrollment modes (audit F-03). "secret" is the original behaviour: the shared AGENT_SECRET authorizes
// a first enrolment. "token" requires a single-use token issued for that exact AgentID; the shared
// secret no longer enrols anyone. Renewal over mTLS is unaffected by the mode.
const (
	EnrollmentModeSecret = "secret"
	EnrollmentModeToken  = "token"
)

// WithEnrollmentMode selects how first enrolment is authorized. Empty means "secret".
func (h *Handler) WithEnrollmentMode(mode string) *Handler {
	h.enrollmentMode = mode
	return h
}

func (h *Handler) tokenEnrollment() bool { return h.enrollmentMode == EnrollmentModeToken }

const (
	enrollTokenDefaultTTL = 24 * time.Hour
	enrollTokenMaxTTL     = 7 * 24 * time.Hour
	enrollTokenPrefix     = "bas_enr_"
)

// agentIDForHostname mirrors agent/identity.go: hex(SHA-256(hostname))[:16], with the hostname exactly
// as the operating system reports it (case preserved).
func agentIDForHostname(hostname string) string {
	sum := sha256.Sum256([]byte(hostname))
	return hex.EncodeToString(sum[:])[:16]
}

// newEnrollmentToken returns 256 bits of randomness with a recognisable prefix, so secret scanners can find a leaked one.
func newEnrollmentToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return enrollTokenPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashEnrollmentToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// enrollThrottle limits failed token attempts per client address so a token cannot be guessed online.
type enrollThrottle struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

const (
	enrollMaxFailures = 20
	enrollWindow      = 10 * time.Minute
)

func (t *enrollThrottle) recent(ip string, now time.Time) []time.Time {
	kept := t.failures[ip][:0]
	for _, ts := range t.failures[ip] {
		if now.Sub(ts) < enrollWindow {
			kept = append(kept, ts)
		}
	}
	if len(kept) == 0 {
		delete(t.failures, ip)
		return nil
	}
	t.failures[ip] = kept
	return kept
}

func (t *enrollThrottle) blocked(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failures == nil {
		return false
	}
	return len(t.recent(ip, time.Now())) >= enrollMaxFailures
}

func (t *enrollThrottle) fail(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failures == nil {
		t.failures = map[string][]time.Time{}
	}
	now := time.Now()
	t.recent(ip, now)
	t.failures[ip] = append(t.failures[ip], now)
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return v
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// POST /api/enrollment-tokens -- issues a single-use enrolment token for one agent. The token is shown
// once; only its SHA-256 is stored. Admin-only (the route group enforces the permission).
func (h *Handler) CreateEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AgentID  string `json:"agentId"`
		Hostname string `json:"hostname"`
		TTLHours *int   `json:"ttlHours"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	agentID := strings.TrimSpace(body.AgentID)
	hostname := body.Hostname
	switch {
	case agentID != "" && hostname != "":
		jsonError(w, "give either agentId or hostname, not both", http.StatusBadRequest)
		return
	case agentID == "" && strings.TrimSpace(hostname) == "":
		jsonError(w, "agentId or hostname is required", http.StatusBadRequest)
		return
	case agentID == "":
		if len(hostname) > 255 {
			jsonError(w, "hostname too long", http.StatusBadRequest)
			return
		}
		agentID = agentIDForHostname(hostname)
	case !agentIDPattern.MatchString(agentID):
		jsonError(w, "invalid agentId — expected 16 lowercase hex characters", http.StatusBadRequest)
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

	token, err := newEnrollmentToken()
	if err != nil {
		jsonError(w, "could not generate a token", http.StatusInternalServerError)
		return
	}

	createdBy := ""
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		createdBy = claims.UserID
	}
	var id string
	var expires time.Time
	err = h.db.QueryRow(r.Context(), `
		INSERT INTO agent_enrollment_tokens (token_hash, agent_id, note, created_by, expires_at)
		VALUES ($1, $2, $3, $4, NOW() + make_interval(secs => $5))
		RETURNING id, expires_at`,
		hashEnrollmentToken(token), agentID, note, createdBy, ttl.Seconds()).Scan(&id, &expires)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "enrollment_token.create", agentID, map[string]any{"tokenId": id, "note": note, "expiresAt": expires}, "ok")
	respond(w, map[string]any{"id": id, "token": token, "agentId": agentID, "expiresAt": expires})
}

// GET /api/enrollment-tokens -- recent tokens with their state. Never returns a token or its hash.
func (h *Handler) ListEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(), `
		SELECT id, agent_id, note, created_by, created_at, expires_at, used_at,
		       CASE WHEN revoked THEN 'revoked'
		            WHEN used_at IS NOT NULL THEN 'used'
		            WHEN expires_at <= NOW() THEN 'expired'
		            ELSE 'pending' END
		  FROM agent_enrollment_tokens ORDER BY created_at DESC LIMIT 500`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, agentID, note, createdBy, status string
		var createdAt, expiresAt time.Time
		var usedAt *time.Time
		if err := rows.Scan(&id, &agentID, &note, &createdBy, &createdAt, &expiresAt, &usedAt, &status); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out = append(out, map[string]any{
			"id": id, "agentId": agentID, "note": note, "createdBy": createdBy,
			"createdAt": createdAt, "expiresAt": expiresAt, "usedAt": usedAt, "status": status,
		})
	}
	respond(w, out)
}

// DELETE /api/enrollment-tokens/{id} -- revokes a token that has not been used yet. Admin-only.
func (h *Handler) RevokeEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var agentID string
	err := h.db.QueryRow(r.Context(),
		`UPDATE agent_enrollment_tokens SET revoked = true WHERE id::text = $1 AND used_at IS NULL AND revoked = false RETURNING agent_id`,
		id).Scan(&agentID)
	if err != nil {
		jsonError(w, "token not found, already used or already revoked", http.StatusNotFound)
		return
	}
	h.auditLog(r, "enrollment_token.revoke", agentID, map[string]any{"tokenId": id}, "ok")
	respond(w, map[string]string{"id": id, "status": "revoked"})
}
