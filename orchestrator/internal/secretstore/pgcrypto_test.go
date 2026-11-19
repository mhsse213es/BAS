package secretstore_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/secretstore"
	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

// sentinel is a value that must never appear in the database, in an error, or in a log, in plaintext.
const sentinel = "BAS-SIM-SECRET-7f3a91"

func newKeyText(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// withStore runs fn against a fresh database that has the secret store schema, with a store keyed by key.
func withStore(t *testing.T, key string, fn func(ctx context.Context, pool *pgxpool.Pool, s *secretstore.PGStore)) {
	t.Helper()
	tdb := testutil.NewTestDB(t)
	tdb.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureSecretStoreSchema(ctx, pool); err != nil {
			t.Fatalf("schema: %v", err)
		}
		s, err := secretstore.NewPGStore(pool, key)
		if err != nil {
			t.Fatalf("NewPGStore: %v", err)
		}
		fn(ctx, pool, s)
	})
}

func TestPGStoreRoundTrip(t *testing.T) {
	key := newKeyText(t)
	withStore(t, key, func(ctx context.Context, pool *pgxpool.Pool, s *secretstore.PGStore) {
		ref := "cred:siem_configs:row-1:token"
		if err := s.Put(ctx, ref, sentinel); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := s.Get(ctx, ref)
		if err != nil || got != sentinel {
			t.Fatalf("Get = %q, %v; want the stored value", got, err)
		}
		// The row holds ciphertext: the plaintext bytes are not present in the stored column.
		var at int
		if err := pool.QueryRow(ctx,
			`SELECT position($1::bytea in value_enc) FROM credential_secrets WHERE ref = $2`,
			[]byte(sentinel), ref).Scan(&at); err != nil {
			t.Fatalf("read stored bytes: %v", err)
		}
		if at != 0 {
			t.Errorf("plaintext found in value_enc at offset %d", at)
		}
	})
}

func TestPGStoreOverwriteAndDelete(t *testing.T) {
	withStore(t, newKeyText(t), func(ctx context.Context, _ *pgxpool.Pool, s *secretstore.PGStore) {
		ref := "cred:detection_connectors:row-2:api_token"
		if err := s.Put(ctx, ref, "first"); err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, ref, "second"); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.Get(ctx, ref); got != "second" {
			t.Errorf("after overwrite Get = %q, want second", got)
		}
		if err := s.Delete(ctx, ref); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := s.Get(ctx, ref); !errors.Is(err, secretstore.ErrNotFound) {
			t.Errorf("Get after delete: err = %v, want ErrNotFound", err)
		}
		if err := s.Delete(ctx, ref); err != nil {
			t.Errorf("deleting a missing reference: %v", err)
		}
	})
}

func TestPGStoreMissingReference(t *testing.T) {
	withStore(t, newKeyText(t), func(ctx context.Context, _ *pgxpool.Pool, s *secretstore.PGStore) {
		if _, err := s.Get(ctx, "cred:siem_configs:none:token"); !errors.Is(err, secretstore.ErrNotFound) {
			t.Errorf("Get of a missing reference: err = %v, want ErrNotFound", err)
		}
	})
}

// A different key never yields a value. It is an error, and the error names neither key nor value.
func TestPGStoreWrongKeyIsErrorNotValue(t *testing.T) {
	right, wrong := newKeyText(t), newKeyText(t)
	withStore(t, right, func(ctx context.Context, pool *pgxpool.Pool, s *secretstore.PGStore) {
		ref := "cred:sso_configs:row-3:client_secret"
		if err := s.Put(ctx, ref, sentinel); err != nil {
			t.Fatal(err)
		}
		other, err := secretstore.NewPGStore(pool, wrong)
		if err != nil {
			t.Fatal(err)
		}
		got, err := other.Get(ctx, ref)
		if err == nil {
			t.Fatalf("a wrong key returned %q", got)
		}
		for _, leak := range []string{sentinel, right, wrong} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("error text carries secret material")
			}
		}
	})
}

func TestPGStoreRefusesEmptyAndMalformed(t *testing.T) {
	withStore(t, newKeyText(t), func(ctx context.Context, _ *pgxpool.Pool, s *secretstore.PGStore) {
		if err := s.Put(ctx, "cred:siem_configs:row-4:token", ""); !errors.Is(err, secretstore.ErrEmptyValue) {
			t.Errorf("empty value: err = %v, want ErrEmptyValue", err)
		}
		if err := s.Put(ctx, "cred:siem_configs:../x:token", sentinel); !errors.Is(err, secretstore.ErrBadRef) {
			t.Errorf("malformed reference: err = %v, want ErrBadRef", err)
		}
	})
}

func TestNewPGStoreRejectsShortKey(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := secretstore.NewPGStore(nil, short); err == nil {
		t.Error("a short key was accepted")
	}
}
