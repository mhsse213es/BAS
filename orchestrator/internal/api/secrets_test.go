package api

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/secretstore"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// credTestKey is base64 of 32 bytes, the format the store requires.
const credTestKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

// credHandler returns a handler on pool with the credential store attached (nil when store is nil).
func credHandler(t *testing.T, pool *pgxpool.Pool, store secretstore.Store) *Handler {
	t.Helper()
	h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	if store != nil {
		h.WithSecretStore(store)
	}
	return h
}

// The reference column wins over the plaintext column once a reference exists. An empty reference keeps the plaintext value,
// so rows that have not been migrated behave exactly as before.
func TestSIEMConfigResolvesReferenceColumns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureSecretStoreSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		store, err := secretstore.NewPGStore(pool, credTestKey)
		if err != nil {
			t.Fatal(err)
		}
		ref, _ := secretstore.MakeRef("siem_configs", "siem-ref-1", "token")
		if err := store.Put(ctx, ref, "stored-token"); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO siem_configs (id, name, provider, console_url, token, token_ref)
			VALUES ('siem-ref-1', 'ref', 'splunk', 'https://siem.test', 'stale-plaintext', $1)`, ref); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO siem_configs (id, name, provider, console_url, token)
			VALUES ('siem-plain-1', 'plain', 'splunk', 'https://siem.test', 'plain-token')`); err != nil {
			t.Fatal(err)
		}

		h := credHandler(t, pool, store)
		cfg, err := h.loadSIEMConfig(ctx, "siem-ref-1")
		if err != nil {
			t.Fatalf("loadSIEMConfig with a reference: %v", err)
		}
		if cfg.Token != "stored-token" {
			t.Fatalf("token = %q, want the stored value, not the plaintext column", cfg.Token)
		}

		plain, err := h.loadSIEMConfig(ctx, "siem-plain-1")
		if err != nil || plain.Token != "plain-token" {
			t.Fatalf("unmigrated row: token = %q, err = %v; want the plaintext value", plain.Token, err)
		}

		// Fail closed: a reference with no store must not fall back to the plaintext column.
		noStore := credHandler(t, pool, nil)
		if _, err := noStore.loadSIEMConfig(ctx, "siem-ref-1"); err == nil {
			t.Fatal("a reference with no store returned a config; it must fail")
		}
	})
}

func TestDetectionConnectorResolvesReferenceColumns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureSecretStoreSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		store, err := secretstore.NewPGStore(pool, credTestKey)
		if err != nil {
			t.Fatal(err)
		}
		tokRef, _ := secretstore.MakeRef("detection_connectors", "det-ref-1", "api_token")
		if err := store.Put(ctx, tokRef, "stored-api-token"); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO detection_connectors (id, name, provider, api_token, api_token_ref)
			VALUES ('det-ref-1', 'ref', 'elastic', 'stale-plaintext', $1)`, tokRef); err != nil {
			t.Fatal(err)
		}

		cfg, err := credHandler(t, pool, store).loadDetectionConnector(ctx, "det-ref-1")
		if err != nil {
			t.Fatalf("loadDetectionConnector: %v", err)
		}
		if cfg.APIToken != "stored-api-token" {
			t.Fatalf("api token = %q, want the stored value", cfg.APIToken)
		}
		if _, err := credHandler(t, pool, nil).loadDetectionConnector(ctx, "det-ref-1"); err == nil {
			t.Fatal("a reference with no store returned a connector; it must fail")
		}
	})
}

func TestActionConnectorResolvesReferenceColumns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureSecretStoreSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		store, err := secretstore.NewPGStore(pool, credTestKey)
		if err != nil {
			t.Fatal(err)
		}
		secRef, _ := secretstore.MakeRef("action_connectors", "act-ref-1", "client_secret")
		if err := store.Put(ctx, secRef, "stored-client-secret"); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO action_connectors (id, name, provider, client_secret, client_secret_ref)
			VALUES ('act-ref-1', 'ref', 'defender', 'stale-plaintext', $1)`, secRef); err != nil {
			t.Fatal(err)
		}

		cfg, _, err := credHandler(t, pool, store).loadResponseConnector(ctx, "act-ref-1")
		if err != nil {
			t.Fatalf("loadResponseConnector: %v", err)
		}
		if cfg.ClientSecret != "stored-client-secret" {
			t.Fatalf("client secret = %q, want the stored value", cfg.ClientSecret)
		}
		if _, _, err := credHandler(t, pool, nil).loadResponseConnector(ctx, "act-ref-1"); err == nil {
			t.Fatal("a reference with no store returned a connector; it must fail")
		}
	})
}
