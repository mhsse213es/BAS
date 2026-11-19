package vault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/audspect/bas/internal/envelope"
	"github.com/audspect/bas/internal/kms"
)

// fakeVault implements the three transit endpoints the provider uses. It is a test double, not Vault.
type fakeVault struct {
	mu       sync.Mutex
	token    string
	keys     map[string][]byte
	deleted  map[string]bool
	exported map[string]bool
	seen     []string
}

func newFakeVault(t *testing.T, token string) (*fakeVault, *httptest.Server) {
	t.Helper()
	f := &fakeVault{token: token, keys: map[string][]byte{}, deleted: map[string]bool{}, exported: map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeVault) addKey(t *testing.T, name string) {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[name] = k
}

func (f *fakeVault) delete(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted[name] = true
}

func (f *fakeVault) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	if r.Header.Get("X-Vault-Token") != f.token {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/") // v1, transit, op, name
	if len(parts) != 4 || parts[0] != "v1" || parts[1] != "transit" {
		http.NotFound(w, r)
		return
	}
	op, name := parts[2], parts[3]
	key, ok := f.keys[name]
	if !ok || f.deleted[name] {
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
		return
	}
	switch {
	case r.Method == http.MethodGet && op == "keys":
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"exportable": f.exported[name]}})
	case r.Method == http.MethodPost && op == "encrypt":
		var in struct{ Plaintext string }
		json.NewDecoder(r.Body).Decode(&in)
		plain, _ := base64.StdEncoding.DecodeString(in.Plaintext)
		ct := seal(key, plain)
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ciphertext": "vault:v1:" + ct}})
	case r.Method == http.MethodPost && op == "decrypt":
		var in struct{ Ciphertext string }
		json.NewDecoder(r.Body).Decode(&in)
		raw := strings.TrimPrefix(in.Ciphertext, "vault:v1:")
		plain, err := open(key, raw)
		if err != nil {
			http.Error(w, `{"errors":["decryption failed"]}`, http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(plain)}})
	default:
		http.NotFound(w, r)
	}
}

func seal(key, plain []byte) string {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	return base64.StdEncoding.EncodeToString(append(nonce, gcm.Seal(nil, nonce, plain, nil)...))
}

func open(key []byte, b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("short")
	}
	return gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
}

func newProvider(t *testing.T, srv *httptest.Server, token string) *Provider {
	t.Helper()
	p, err := New(Config{Address: srv.URL, Token: token, AllowPlainHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Wrap and unwrap go through Vault, carry the token, and recover the data key.
func TestWrapUnwrapThroughVault(t *testing.T) {
	f, srv := newFakeVault(t, "tok-1")
	f.addKey(t, "audspect-kek")
	p := newProvider(t, srv, "tok-1")
	ctx := context.Background()
	dek := bytes.Repeat([]byte{7}, 32)
	wrapped, err := p.WrapDEK(ctx, "audspect-kek", dek)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("wrapped form contains the data key")
	}
	got, err := p.UnwrapDEK(ctx, "audspect-kek", wrapped)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap = %x, %v", got, err)
	}
}

// A wrong token is refused, and nothing is unwrapped.
func TestWrongTokenIsRefused(t *testing.T) {
	f, srv := newFakeVault(t, "tok-1")
	f.addKey(t, "audspect-kek")
	p := newProvider(t, srv, "not-the-token")
	if _, err := p.Status(context.Background(), "audspect-kek"); !errors.Is(err, kms.ErrStatusUnknown) {
		t.Fatalf("wrong token: err = %v, want ErrStatusUnknown", err)
	}
}

// A deleted key is reported as revoked, which the envelope layer treats as data unreadable.
func TestDeletedKeyReportsRevoked(t *testing.T) {
	f, srv := newFakeVault(t, "tok-1")
	f.addKey(t, "audspect-kek")
	p := newProvider(t, srv, "tok-1")
	f.delete("audspect-kek")
	s, err := p.Status(context.Background(), "audspect-kek")
	if err != nil || s != kms.StatusRevoked {
		t.Fatalf("deleted key: status %q, err %v; want revoked", s, err)
	}
}

// An exportable transit key is refused: it could leave Vault, so it cannot be a KEK.
func TestExportableKeyIsRefused(t *testing.T) {
	f, srv := newFakeVault(t, "tok-1")
	f.addKey(t, "leaky")
	f.exported["leaky"] = true
	p := newProvider(t, srv, "tok-1")
	if s, err := p.Status(context.Background(), "leaky"); err == nil || s == kms.StatusActive {
		t.Fatalf("exportable key must be refused, got status %q, err %v", s, err)
	}
}

// Key names are restricted, so a name cannot steer the request to another Vault path.
func TestKeyNameIsRestricted(t *testing.T) {
	_, srv := newFakeVault(t, "tok-1")
	p := newProvider(t, srv, "tok-1")
	for _, bad := range []string{"", "../sys/seal", "a/b", "name with space", strings.Repeat("x", 129)} {
		if _, err := p.WrapDEK(context.Background(), kms.KeyRef(bad), []byte("x")); err == nil {
			t.Errorf("name %q must be refused", bad)
		}
	}
}

// Plain http is refused unless explicitly allowed, and the address must be absolute.
func TestConfigRefusesPlainHTTPByDefault(t *testing.T) {
	if _, err := New(Config{Address: "http://vault.example:8200", Token: "t"}); err == nil {
		t.Error("plain http must be refused by default")
	}
	if _, err := New(Config{Address: "vault.example:8200", Token: "t"}); err == nil {
		t.Error("an address without a scheme must be refused")
	}
	if _, err := New(Config{Address: "https://vault.example:8200", Token: ""}); err == nil {
		t.Error("a missing token must be refused")
	}
}

// End to end: the envelope layer over Vault. Deleting the key in Vault makes stored data unreadable.
func TestEnvelopeOverVaultFailsClosedAfterDelete(t *testing.T) {
	f, srv := newFakeVault(t, "tok-1")
	f.addKey(t, "audspect-kek")
	p := newProvider(t, srv, "tok-1")
	m := envelope.New(p, envelope.Config{})
	ctx := context.Background()
	blob, err := m.Seal(ctx, "audspect-kek", "connector_credentials", []byte("svc-password"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := m.Open(ctx, "connector_credentials", blob); err != nil || string(got) != "svc-password" {
		t.Fatalf("baseline open: %q, %v", got, err)
	}
	f.delete("audspect-kek")
	if _, err := m.Open(ctx, "connector_credentials", blob); !errors.Is(err, kms.ErrKeyRevoked) {
		t.Fatalf("after Vault key deletion: err = %v, want ErrKeyRevoked", err)
	}
}
