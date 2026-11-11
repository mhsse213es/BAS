package secretstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestOpenConfiguredRejectsUnknownKMS(t *testing.T) {
	if _, err := OpenConfigured(nil, "", envOf(map[string]string{"BAS_KMS": "vaukt"})); err == nil {
		t.Fatal("an unknown BAS_KMS value must be an error, not a silent legacy fallback")
	}
}

func TestOpenConfiguredVaultNeedsAllSettings(t *testing.T) {
	if _, err := OpenConfigured(nil, "", envOf(map[string]string{"BAS_KMS": "vault"})); err == nil {
		t.Fatal("vault without settings must be an error")
	}
}

func TestOpenConfiguredVaultRejectsPlainHTTPByDefault(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := OpenConfigured(nil, "", envOf(map[string]string{
		"BAS_KMS": "vault", "BAS_VAULT_ADDR": "http://vault.example:8200",
		"BAS_VAULT_KEY_NAME": "audspect-kek", "BAS_VAULT_TOKEN_FILE": tok,
	}))
	if err == nil {
		t.Fatal("plain http must be refused unless BAS_VAULT_ALLOW_PLAIN_HTTP=1")
	}
}

func TestOpenConfiguredMissingTokenFileIsAnError(t *testing.T) {
	_, err := OpenConfigured(nil, "", envOf(map[string]string{
		"BAS_KMS": "vault", "BAS_VAULT_ADDR": "https://vault.example:8200",
		"BAS_VAULT_KEY_NAME": "audspect-kek", "BAS_VAULT_TOKEN_FILE": filepath.Join(t.TempDir(), "absent"),
	}))
	if err == nil {
		t.Fatal("a missing token file must be an error")
	}
}

func TestNoLegacyReportsNotFound(t *testing.T) {
	if _, err := (NoLegacy{}).Get(context.Background(), "cred:x:y:z"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("NoLegacy.Get = %v, want ErrNotFound", err)
	}
}
