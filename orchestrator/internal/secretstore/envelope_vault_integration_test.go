package secretstore_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/envelope"
	"github.com/audspect/bas/internal/kms"
	"github.com/audspect/bas/internal/kms/vault"
	"github.com/audspect/bas/internal/secretstore"
	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Runs connector-credential storage against a real Vault and a real Postgres. Skipped unless VAULT_TEST_ADDR and
// VAULT_TEST_TOKEN are set. The transit key VAULT_TEST_KEY (default "credentials-kek") must exist with
// deletion_allowed set, because the test deletes it to prove revocation.
func TestIntegrationCredentialsThroughVault(t *testing.T) {
	addr, token := os.Getenv("VAULT_TEST_ADDR"), os.Getenv("VAULT_TEST_TOKEN")
	if addr == "" || token == "" {
		t.Skip("set VAULT_TEST_ADDR and VAULT_TEST_TOKEN to run against a real Vault")
	}
	keyName := os.Getenv("VAULT_TEST_KEY")
	if keyName == "" {
		keyName = "credentials-kek"
	}
	prov, err := vault.New(vault.Config{Address: addr, Token: token, AllowPlainHTTP: strings.HasPrefix(addr, "http://")})
	if err != nil {
		t.Fatal(err)
	}
	mgr := envelope.New(prov, envelope.Config{})
	ctx := context.Background()

	tdb := testutil.NewTestDB(t)
	tdb.RunWithPool(t, func(pool *pgxpool.Pool) {
		if err := db.EnsureSecretStoreSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		primary, err := secretstore.NewEnvelopeStore(pool, mgr, kms.KeyRef(keyName))
		if err != nil {
			t.Fatal(err)
		}
		ref, _ := secretstore.MakeRef("siem_configs", "vault-it", "token")
		if err := primary.Put(ctx, ref, sentinel); err != nil {
			t.Fatalf("put through Vault: %v", err)
		}
		if got, err := primary.Get(ctx, ref); err != nil || got != sentinel {
			t.Fatalf("get through Vault: %q, %v", got, err)
		}
		var blob []byte
		if err := pool.QueryRow(ctx, `SELECT blob FROM credential_secrets_envelope WHERE ref = $1`, ref).Scan(&blob); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(blob, []byte(sentinel)) {
			t.Fatal("plaintext in the database row")
		}

		// Vault only deletes a key whose config allows it. Set that on the test key, then delete it.
		for _, step := range []struct {
			path string
			body string
		}{{"/v1/transit/keys/" + keyName + "/config", `{"deletion_allowed":true}`}} {
			cfg, _ := http.NewRequest(http.MethodPost, strings.TrimRight(addr, "/")+step.path, strings.NewReader(step.body))
			cfg.Header.Set("X-Vault-Token", token)
			cr, err := (&http.Client{Timeout: 10 * time.Second}).Do(cfg)
			if err != nil {
				t.Fatal(err)
			}
			cr.Body.Close()
			if cr.StatusCode != http.StatusNoContent && cr.StatusCode != http.StatusOK {
				t.Fatalf("allow deletion: HTTP %d", cr.StatusCode)
			}
		}

		// Delete the key in Vault. The stored credential must then be unreadable, not merely unfetched.
		req, _ := http.NewRequest(http.MethodDelete, strings.TrimRight(addr, "/")+"/v1/transit/keys/"+keyName, nil)
		req.Header.Set("X-Vault-Token", token)
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
			t.Fatalf("delete key: HTTP %d", resp.StatusCode)
		}
		if _, err := primary.Get(ctx, ref); !errors.Is(err, kms.ErrKeyRevoked) {
			t.Fatalf("after Vault key deletion: err = %v, want ErrKeyRevoked", err)
		}
	})
}
