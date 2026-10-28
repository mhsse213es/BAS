package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

const goodPassphrase = "Ab3dEf6hIj9LmN" // 14 alphanumeric

func TestValidRecoveryPassphrase(t *testing.T) {
	for in, want := range map[string]bool{
		goodPassphrase:    true,
		"abcdefghijklmn":  true,
		"12345678901234":  true,
		"Ab3dEf6hIj9Lm":   false, // 13
		"Ab3dEf6hIj9LmNp": false, // 15
		"Ab3dEf6hIj9Lm-":  false, // symbol
		"Ab3dEf6hIj 9LmN": false, // space
		"":                false,
		"Ab3dEf6hIj9Lmé":  false, // non-ASCII letter
	} {
		if got := ValidRecoveryPassphrase(in); got != want {
			t.Errorf("ValidRecoveryPassphrase(%q) = %v, want %v", in, got, want)
		}
	}
}

func recoverReq(user, pass, newPw string) *http.Request {
	b, _ := json.Marshal(map[string]string{"username": user, "passphrase": pass, "newPassword": newPw})
	r := httptest.NewRequest(http.MethodPost, "/api/auth/recover", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func withRecovery(t *testing.T, fn func(h *Handler, pool *pgxpool.Pool)) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, _ = pool.Exec(context.Background(), `DELETE FROM recovery_passphrase`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		fn(h, pool)
	})
}

func TestRecover_NotConfigured_IsRefused(t *testing.T) {
	withRecovery(t, func(h *Handler, pool *pgxpool.Pool) {
		seedUser(t, pool, "rec-nc@x.test", "old-password-123", "admin", true)
		rec := httptest.NewRecorder()
		h.RecoverPassword(rec, recoverReq("rec-nc@x.test", goodPassphrase, "brand-new-pass-1"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 when no recovery passphrase is configured", rec.Code)
		}
	})
}

func TestRecover_CorrectPassphraseResetsAnAdminPassword(t *testing.T) {
	withRecovery(t, func(h *Handler, pool *pgxpool.Pool) {
		if err := SeedRecoveryPassphrase(context.Background(), pool, goodPassphrase); err != nil {
			t.Fatal(err)
		}
		id := seedUser(t, pool, "rec-ok@x.test", "old-password-123", "admin", true)
		_, _ = pool.Exec(context.Background(), `UPDATE users SET must_change_pw = true WHERE id = $1`, id)
		rec := httptest.NewRecorder()
		h.RecoverPassword(rec, recoverReq("rec-ok@x.test", goodPassphrase, "brand-new-pass-1"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var hash string
		var must bool
		_ = pool.QueryRow(context.Background(), `SELECT password_hash, must_change_pw FROM users WHERE id=$1`, id).Scan(&hash, &must)
		if ok, _, _ := auth.VerifyPassword("brand-new-pass-1", hash); !ok {
			t.Error("the new password does not work")
		}
		if ok, _, _ := auth.VerifyPassword("old-password-123", hash); ok {
			t.Error("the old password still works")
		}
		if must {
			t.Error("must_change_pw should be cleared: the person just chose this password")
		}
		// And the login endpoint accepts it.
		lr := httptest.NewRecorder()
		h.Login(lr, loginReq("rec-ok@x.test", "brand-new-pass-1"))
		if lr.Code != http.StatusOK {
			t.Errorf("login with the recovered password = %d", lr.Code)
		}
	})
}

func TestRecover_WrongPassphraseAndUnknownUserGiveTheSameAnswer(t *testing.T) {
	withRecovery(t, func(h *Handler, pool *pgxpool.Pool) {
		_ = SeedRecoveryPassphrase(context.Background(), pool, goodPassphrase)
		id := seedUser(t, pool, "rec-wrong@x.test", "old-password-123", "admin", true)
		a, b := httptest.NewRecorder(), httptest.NewRecorder()
		h.RecoverPassword(a, recoverReq("rec-wrong@x.test", "Zz9yXx8wVv7UuT", "brand-new-pass-1"))
		h.RecoverPassword(b, recoverReq("nobody@x.test", goodPassphrase, "brand-new-pass-1"))
		if a.Code != http.StatusUnauthorized || b.Code != http.StatusUnauthorized {
			t.Fatalf("wrong passphrase=%d unknown user=%d, want 401 both", a.Code, b.Code)
		}
		if a.Body.String() != b.Body.String() {
			t.Errorf("the two failures must be indistinguishable:\n%s\n%s", a.Body.String(), b.Body.String())
		}
		var hash string
		_ = pool.QueryRow(context.Background(), `SELECT password_hash FROM users WHERE id=$1`, id).Scan(&hash)
		if ok, _, _ := auth.VerifyPassword("old-password-123", hash); !ok {
			t.Error("a failed recovery changed the password")
		}
	})
}

func TestRecover_OnlyLocalAdminAccountsAreRecoverable(t *testing.T) {
	withRecovery(t, func(h *Handler, pool *pgxpool.Pool) {
		_ = SeedRecoveryPassphrase(context.Background(), pool, goodPassphrase)
		seedUser(t, pool, "rec-viewer@x.test", "old-password-123", "viewer", true)
		sso := seedUser(t, pool, "rec-sso@x.test", "old-password-123", "admin", true)
		_, _ = pool.Exec(context.Background(), `UPDATE users SET auth_source='sso' WHERE id=$1`, sso)
		for _, u := range []string{"rec-viewer@x.test", "rec-sso@x.test"} {
			rec := httptest.NewRecorder()
			h.RecoverPassword(rec, recoverReq(u, goodPassphrase, "brand-new-pass-1"))
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s: status = %d, want 401: only local admin accounts can be recovered this way", u, rec.Code)
			}
		}
	})
}

func TestRecover_DisabledAdminStaysDisabled(t *testing.T) {
	withRecovery(t, func(h *Handler, pool *pgxpool.Pool) {
		_ = SeedRecoveryPassphrase(context.Background(), pool, goodPassphrase)
		seedUser(t, pool, "rec-off@x.test", "old-password-123", "admin", false)
		rec := httptest.NewRecorder()
		h.RecoverPassword(rec, recoverReq("rec-off@x.test", goodPassphrase, "brand-new-pass-1"))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d: recovery must not re-enable an account an administrator disabled", rec.Code)
		}
	})
}

func TestRecover_WeakNewPasswordIsRejectedWithoutSpendingAnAttempt(t *testing.T) {
	withRecovery(t, func(h *Handler, pool *pgxpool.Pool) {
		_ = SeedRecoveryPassphrase(context.Background(), pool, goodPassphrase)
		seedUser(t, pool, "rec-weak@x.test", "old-password-123", "admin", true)
		rec := httptest.NewRecorder()
		h.RecoverPassword(rec, recoverReq("rec-weak@x.test", goodPassphrase, "short"))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestRecover_FiveWrongAttemptsLockRecoveryEvenForTheRightPassphrase(t *testing.T) {
	withRecovery(t, func(h *Handler, pool *pgxpool.Pool) {
		_ = SeedRecoveryPassphrase(context.Background(), pool, goodPassphrase)
		seedUser(t, pool, "rec-lock@x.test", "old-password-123", "admin", true)
		for i := 0; i < 5; i++ {
			rec := httptest.NewRecorder()
			h.RecoverPassword(rec, recoverReq("rec-lock@x.test", "Zz9yXx8wVv7UuT", "brand-new-pass-1"))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("attempt %d status = %d, want 401", i+1, rec.Code)
			}
		}
		rec := httptest.NewRecorder()
		h.RecoverPassword(rec, recoverReq("rec-lock@x.test", goodPassphrase, "brand-new-pass-1"))
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429 while locked, even with the right passphrase", rec.Code)
		}
	})
}

func TestRecover_SuccessClearsEarlierFailures(t *testing.T) {
	withRecovery(t, func(h *Handler, pool *pgxpool.Pool) {
		_ = SeedRecoveryPassphrase(context.Background(), pool, goodPassphrase)
		seedUser(t, pool, "rec-clear@x.test", "old-password-123", "admin", true)
		for i := 0; i < 3; i++ {
			h.RecoverPassword(httptest.NewRecorder(), recoverReq("rec-clear@x.test", "Zz9yXx8wVv7UuT", "brand-new-pass-1"))
		}
		rec := httptest.NewRecorder()
		h.RecoverPassword(rec, recoverReq("rec-clear@x.test", goodPassphrase, "brand-new-pass-1"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		var n int
		_ = pool.QueryRow(context.Background(), `SELECT failed_attempts FROM recovery_passphrase WHERE id=1`).Scan(&n)
		if n != 0 {
			t.Errorf("failed_attempts = %d after a success, want 0", n)
		}
	})
}

func TestSeedRecoveryPassphrase_StoresOnlyAHashAndRotates(t *testing.T) {
	withRecovery(t, func(h *Handler, pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := SeedRecoveryPassphrase(ctx, pool, goodPassphrase); err != nil {
			t.Fatal(err)
		}
		var hash string
		_ = pool.QueryRow(ctx, `SELECT hash FROM recovery_passphrase WHERE id=1`).Scan(&hash)
		if hash == "" || strings.Contains(hash, goodPassphrase) {
			t.Fatalf("the stored value must be a hash, got %q", hash)
		}
		// Same value again: untouched (no rehash, counters kept).
		_, _ = pool.Exec(ctx, `UPDATE recovery_passphrase SET failed_attempts = 2 WHERE id=1`)
		_ = SeedRecoveryPassphrase(ctx, pool, goodPassphrase)
		var n int
		var hash2 string
		_ = pool.QueryRow(ctx, `SELECT failed_attempts, hash FROM recovery_passphrase WHERE id=1`).Scan(&n, &hash2)
		if n != 2 || hash2 != hash {
			t.Errorf("re-seeding the same passphrase must change nothing: attempts=%d hashChanged=%v", n, hash2 != hash)
		}
		// A new value (edited setup.conf) replaces it and clears the counters.
		if err := SeedRecoveryPassphrase(ctx, pool, "Qq1wWe2rRt3tYy"); err != nil {
			t.Fatal(err)
		}
		_ = pool.QueryRow(ctx, `SELECT failed_attempts, hash FROM recovery_passphrase WHERE id=1`).Scan(&n, &hash2)
		if n != 0 || hash2 == hash {
			t.Errorf("a new passphrase must replace the hash and clear failures: attempts=%d replaced=%v", n, hash2 != hash)
		}
	})
}

func TestSeedRecoveryPassphrase_BlankKeepsAndInvalidIsRefused(t *testing.T) {
	withRecovery(t, func(h *Handler, pool *pgxpool.Pool) {
		ctx := context.Background()
		_ = SeedRecoveryPassphrase(ctx, pool, goodPassphrase)
		if err := SeedRecoveryPassphrase(ctx, pool, ""); err != nil {
			t.Errorf("blank (an upgrade with no value) must keep the stored one: %v", err)
		}
		if err := SeedRecoveryPassphrase(ctx, pool, "too-short"); err == nil {
			t.Error("a malformed passphrase must be refused, not stored")
		}
		var c int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM recovery_passphrase`).Scan(&c)
		if c != 1 {
			t.Errorf("rows = %d", c)
		}
	})
}
