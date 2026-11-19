package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/envelope"
	"github.com/audspect/bas/internal/kms"
)

// Integration tests run against a real Vault when VAULT_TEST_ADDR and VAULT_TEST_TOKEN are set, for example a
// local dev server with the transit engine mounted at "transit". They are skipped otherwise.
//
//	VAULT_TEST_ADDR=http://127.0.0.1:18200 VAULT_TEST_TOKEN=... go test ./internal/kms/vault/ -run Integration
func integrationEnv(t *testing.T) (addr, token string) {
	t.Helper()
	addr, token = os.Getenv("VAULT_TEST_ADDR"), os.Getenv("VAULT_TEST_TOKEN")
	if addr == "" || token == "" {
		t.Skip("set VAULT_TEST_ADDR and VAULT_TEST_TOKEN to run against a real Vault")
	}
	return addr, token
}

// vaultAdmin performs the setup calls the tests need: create or delete a transit key.
func vaultAdmin(t *testing.T, addr, token, method, path string, body any) int {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, strings.TrimRight(addr, "/")+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", token)
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// uniqueKeyName keeps reruns from colliding with keys left by an earlier run.
func uniqueKeyName(prefix string) kms.KeyRef {
	return kms.KeyRef(fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()))
}

func TestIntegrationWrapUnwrapAndStatus(t *testing.T) {
	addr, token := integrationEnv(t)
	name := uniqueKeyName("bas-it-kek")
	if code := vaultAdmin(t, addr, token, http.MethodPost, "/v1/transit/keys/"+string(name), map[string]any{"exportable": false}); code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("create key: HTTP %d (is the transit engine mounted?)", code)
	}
	p, err := New(Config{Address: addr, Token: token, AllowPlainHTTP: strings.HasPrefix(addr, "http://")})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	s, err := p.Status(ctx, name)
	if err != nil || s != kms.StatusActive {
		t.Fatalf("non-exportable key: status %q, err %v; want active", s, err)
	}
	dek := bytes.Repeat([]byte{0x42}, 32)
	wrapped, err := p.WrapDEK(ctx, name, dek)
	if err != nil {
		t.Fatalf("wrap through Vault: %v", err)
	}
	got, err := p.UnwrapDEK(ctx, name, wrapped)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap through Vault: %x, %v", got, err)
	}
}

func TestIntegrationExportableKeyRefused(t *testing.T) {
	addr, token := integrationEnv(t)
	name := uniqueKeyName("bas-it-exportable")
	if code := vaultAdmin(t, addr, token, http.MethodPost, "/v1/transit/keys/"+string(name), map[string]any{"exportable": true}); code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("create exportable key: HTTP %d", code)
	}
	p, _ := New(Config{Address: addr, Token: token, AllowPlainHTTP: strings.HasPrefix(addr, "http://")})
	if s, err := p.Status(context.Background(), name); err == nil || s == kms.StatusActive {
		t.Fatalf("real exportable key must be refused, got %q, %v", s, err)
	}
}

// Deleting the key in Vault revokes it: stored data becomes unreadable through the envelope layer.
func TestIntegrationDeletedKeyRevokesEnvelopeData(t *testing.T) {
	addr, token := integrationEnv(t)
	name := uniqueKeyName("bas-it-revoke")
	if code := vaultAdmin(t, addr, token, http.MethodPost, "/v1/transit/keys/"+string(name), map[string]any{"exportable": false}); code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("create key: HTTP %d", code)
	}
	// Vault only deletes a key whose config allows it.
	if code := vaultAdmin(t, addr, token, http.MethodPost, "/v1/transit/keys/"+string(name)+"/config", map[string]any{"deletion_allowed": true}); code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("allow deletion: HTTP %d", code)
	}
	p, _ := New(Config{Address: addr, Token: token, AllowPlainHTTP: strings.HasPrefix(addr, "http://")})
	m := envelope.New(p, envelope.Config{})
	ctx := context.Background()
	blob, err := m.Seal(ctx, name, "connector_credentials", []byte("svc-password"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := m.Open(ctx, "connector_credentials", blob); err != nil || string(got) != "svc-password" {
		t.Fatalf("baseline open: %q, %v", got, err)
	}
	if code := vaultAdmin(t, addr, token, http.MethodDelete, "/v1/transit/keys/"+string(name), nil); code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("delete key: HTTP %d (deletion_allowed must be set)", code)
	}
	if _, err := m.Open(ctx, "connector_credentials", blob); !errors.Is(err, kms.ErrKeyRevoked) {
		t.Fatalf("after Vault deletion: err = %v, want ErrKeyRevoked", err)
	}
}
