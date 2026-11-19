package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Console password recovery. An operator sets RECOVERY_PASSPHRASE (14 letters and digits) in setup.conf. Someone who has
// forgotten an administrator password presents it with the account name and a new password. Design choices:
//   - only a hash of the passphrase is stored (recovery_passphrase table), seeded from the environment at start;
//   - only local administrator accounts that are still enabled can be recovered this way: other users ask an
//     administrator, SSO accounts use their identity provider, and a disabled account stays disabled;
//   - the passphrase is checked before the account is looked up and every failure returns the same answer, so the
//     endpoint cannot be used to find out which accounts exist;
//   - five failures lock recovery for 15 minutes (the passphrase is one shared value, so the counter is shared);
//   - sessions that already exist are not revoked (tokens are stateless): rotate JWT_SECRET to end them.
const (
	recoveryPassphraseLen = 14
	recoveryMaxFailures   = 5
	recoveryLockSeconds   = 15 * 60
	recoveryMinPassword   = 10
)

// ValidRecoveryPassphrase reports whether s is exactly 14 ASCII letters and digits.
func ValidRecoveryPassphrase(s string) bool {
	if len(s) != recoveryPassphraseLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// SeedRecoveryPassphrase stores the hash of pass. Blank keeps whatever is stored (an upgrade with no value); a malformed
// value is refused; the same value again changes nothing (counters kept); a different value replaces the hash and clears
// the counters.
func SeedRecoveryPassphrase(ctx context.Context, pool *pgxpool.Pool, pass string) error {
	if pass == "" {
		return nil
	}
	if !ValidRecoveryPassphrase(pass) {
		return errors.New("recovery passphrase must be exactly 14 letters and digits")
	}
	var existing string
	err := pool.QueryRow(ctx, `SELECT hash FROM recovery_passphrase WHERE id = 1`).Scan(&existing)
	if err == nil {
		if ok, _, _ := auth.VerifyPassword(pass, existing); ok {
			return nil
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read recovery passphrase: %w", err)
	}
	hash, err := auth.HashPassword(pass)
	if err != nil {
		return fmt.Errorf("hash recovery passphrase: %w", err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO recovery_passphrase (id, hash) VALUES (1, $1)
		ON CONFLICT (id) DO UPDATE SET hash = EXCLUDED.hash, set_at = now(), failed_attempts = 0, locked_until = NULL`, hash)
	if err != nil {
		return fmt.Errorf("store recovery passphrase: %w", err)
	}
	return nil
}

// POST /api/auth/recover -- public. Body: {"username", "passphrase", "newPassword"}.
func (h *Handler) RecoverPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		Passphrase  string `json:"passphrase"`
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Username == "" || req.Passphrase == "" || req.NewPassword == "" {
		jsonError(w, "username, passphrase and newPassword are required", http.StatusBadRequest)
		return
	}
	if len(req.NewPassword) < recoveryMinPassword {
		jsonError(w, "new password must be at least 10 characters", http.StatusBadRequest)
		return
	}

	var hash string
	var lockedUntil *time.Time
	err := h.db.QueryRow(r.Context(), `SELECT hash, locked_until FROM recovery_passphrase WHERE id = 1`).Scan(&hash, &lockedUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, "password recovery is not configured on this server", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "recovery unavailable", http.StatusInternalServerError)
		return
	}
	if lockedUntil != nil && lockedUntil.After(time.Now()) {
		h.auditLogAs(r, "", "user.recover_password", req.Username, map[string]any{"reason": "locked"}, "fail")
		jsonError(w, "too many failed attempts; try again later", http.StatusTooManyRequests)
		return
	}

	passOK, _, _ := auth.VerifyPassword(req.Passphrase, hash)
	var id, role, authSource string
	var active bool
	lookupErr := h.db.QueryRow(r.Context(),
		`SELECT id, role, is_active, auth_source FROM users WHERE username = $1`, req.Username).Scan(&id, &role, &active, &authSource)
	if !passOK || lookupErr != nil || role != "admin" || authSource == "sso" || !active {
		_, _ = h.db.Exec(r.Context(), `
			UPDATE recovery_passphrase SET
				failed_attempts = failed_attempts + 1,
				locked_until = CASE WHEN failed_attempts + 1 >= $1 THEN now() + make_interval(secs => $2) ELSE locked_until END
			WHERE id = 1`, recoveryMaxFailures, recoveryLockSeconds)
		h.auditLogAs(r, "", "user.recover_password", req.Username, map[string]any{"reason": "invalid details"}, "fail")
		jsonError(w, "invalid recovery details", http.StatusUnauthorized)
		return
	}

	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		jsonError(w, "password hashing failed", http.StatusInternalServerError)
		return
	}
	if _, err := h.db.Exec(r.Context(), `UPDATE users SET password_hash = $1, must_change_pw = false WHERE id = $2`, newHash, id); err != nil {
		jsonError(w, "could not update the password", http.StatusInternalServerError)
		return
	}
	_, _ = h.db.Exec(r.Context(), `UPDATE recovery_passphrase SET failed_attempts = 0, locked_until = NULL WHERE id = 1`)
	h.auditLogAs(r, id, "user.recover_password", id, nil, "ok")
	respond(w, map[string]string{"status": "password reset; sign in with the new password"})
}
