package secretstore_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/envelope"
	"github.com/audspect/bas/internal/kms"
	"github.com/audspect/bas/internal/kms/memprovider"
	"github.com/audspect/bas/internal/secretstore"
	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

const envRef = kms.KeyRef("kek-credentials")

// envFixture is a fresh database with both backends, plus the provider so a test can revoke the KEK.
type envFixture struct {
	pool    *pgxpool.Pool
	prov    *memprovider.Provider
	primary *secretstore.EnvelopeStore
	legacy  *secretstore.PGStore
}

func withEnvFixture(t *testing.T, fn func(ctx context.Context, f envFixture)) {
	t.Helper()
	tdb := testutil.NewTestDB(t)
	tdb.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureSecretStoreSchema(ctx, pool); err != nil {
			t.Fatalf("schema: %v", err)
		}
		prov := memprovider.New()
		if err := prov.CreateKey(envRef); err != nil {
			t.Fatal(err)
		}
		mgr := envelope.New(prov, envelope.Config{})
		primary, err := secretstore.NewEnvelopeStore(pool, mgr, envRef)
		if err != nil {
			t.Fatal(err)
		}
		legacy, err := secretstore.NewPGStore(pool, newKeyText(t))
		if err != nil {
			t.Fatal(err)
		}
		fn(ctx, envFixture{pool: pool, prov: prov, primary: primary, legacy: legacy})
	})
}

func credRef(t *testing.T, id string) string {
	t.Helper()
	ref, err := secretstore.MakeRef("siem_configs", id, "token")
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func TestEnvelopeStoreRoundTripAndNoPlaintextAtRest(t *testing.T) {
	withEnvFixture(t, func(ctx context.Context, f envFixture) {
		ref := credRef(t, "a1")
		if err := f.primary.Put(ctx, ref, sentinel); err != nil {
			t.Fatal(err)
		}
		got, err := f.primary.Get(ctx, ref)
		if err != nil || got != sentinel {
			t.Fatalf("round trip: %q, %v", got, err)
		}
		var blob []byte
		if err := f.pool.QueryRow(ctx, `SELECT blob FROM credential_secrets_envelope WHERE ref = $1`, ref).Scan(&blob); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(blob, []byte(sentinel)) {
			t.Fatal("plaintext appears in the stored envelope")
		}
	})
}

func TestEnvelopeMissingReturnsNotFound(t *testing.T) {
	withEnvFixture(t, func(ctx context.Context, f envFixture) {
		if _, err := f.primary.Get(ctx, credRef(t, "none")); !errors.Is(err, secretstore.ErrNotFound) {
			t.Fatalf("missing: err = %v, want ErrNotFound", err)
		}
	})
}

// A blob copied from one credential field to another must not open: it is bound to its reference.
func TestEnvelopeBlobCannotBeMovedBetweenReferences(t *testing.T) {
	withEnvFixture(t, func(ctx context.Context, f envFixture) {
		src, dst := credRef(t, "src"), credRef(t, "dst")
		if err := f.primary.Put(ctx, src, sentinel); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(ctx,
			`INSERT INTO credential_secrets_envelope (ref, blob) SELECT $1, blob FROM credential_secrets_envelope WHERE ref = $2`,
			dst, src); err != nil {
			t.Fatal(err)
		}
		if _, err := f.primary.Get(ctx, dst); err == nil {
			t.Fatal("a blob moved to another reference must not open")
		}
	})
}

// A revoked KEK makes reads and writes fail with the kms error, never a value.
func TestRevokedKEKRefusesValues(t *testing.T) {
	withEnvFixture(t, func(ctx context.Context, f envFixture) {
		ref := credRef(t, "r1")
		if err := f.primary.Put(ctx, ref, sentinel); err != nil {
			t.Fatal(err)
		}
		f.prov.Revoke(envRef)
		if _, err := f.primary.Get(ctx, ref); !errors.Is(err, kms.ErrKeyRevoked) {
			t.Fatalf("revoked: Get err = %v, want ErrKeyRevoked", err)
		}
		if err := f.primary.Put(ctx, credRef(t, "r2"), "new"); err == nil {
			t.Fatal("writing under a revoked KEK must fail")
		}
	})
}

// The composite reads the primary first and falls back to the legacy row only when the primary has no value.
func TestCompositeFallsBackOnlyWhenPrimaryIsEmpty(t *testing.T) {
	withEnvFixture(t, func(ctx context.Context, f envFixture) {
		legacyOnly, both := credRef(t, "legacy-only"), credRef(t, "both")
		if err := f.legacy.Put(ctx, legacyOnly, "old-value"); err != nil {
			t.Fatal(err)
		}
		if err := f.legacy.Put(ctx, both, "old-both"); err != nil {
			t.Fatal(err)
		}
		if err := f.primary.Put(ctx, both, "new-both"); err != nil {
			t.Fatal(err)
		}
		c := &secretstore.Composite{Primary: f.primary, Legacy: f.legacy}
		if v, err := c.Get(ctx, legacyOnly); err != nil || v != "old-value" {
			t.Fatalf("legacy-only: %q, %v", v, err)
		}
		if v, err := c.Get(ctx, both); err != nil || v != "new-both" {
			t.Fatalf("primary must win: %q, %v", v, err)
		}
	})
}

// A revoked primary key must not be bypassed by the legacy row. Otherwise revocation would be defeated.
func TestCompositeDoesNotFallBackOnRevocation(t *testing.T) {
	withEnvFixture(t, func(ctx context.Context, f envFixture) {
		ref := credRef(t, "revoked")
		if err := f.legacy.Put(ctx, ref, "legacy-copy"); err != nil {
			t.Fatal(err)
		}
		if err := f.primary.Put(ctx, ref, "primary-copy"); err != nil {
			t.Fatal(err)
		}
		f.prov.Revoke(envRef)
		c := &secretstore.Composite{Primary: f.primary, Legacy: f.legacy}
		v, err := c.Get(ctx, ref)
		if !errors.Is(err, kms.ErrKeyRevoked) || v != "" {
			t.Fatalf("revoked primary: value %q, err %v; must be ErrKeyRevoked with no value", v, err)
		}
	})
}

// Writes go to the primary only; the legacy row is left as it was.
func TestCompositePutWritesPrimaryOnly(t *testing.T) {
	withEnvFixture(t, func(ctx context.Context, f envFixture) {
		ref := credRef(t, "w1")
		if err := f.legacy.Put(ctx, ref, "legacy"); err != nil {
			t.Fatal(err)
		}
		c := &secretstore.Composite{Primary: f.primary, Legacy: f.legacy}
		if err := c.Put(ctx, ref, "fresh"); err != nil {
			t.Fatal(err)
		}
		if v, err := f.legacy.Get(ctx, ref); err != nil || v != "legacy" {
			t.Fatalf("legacy row must be untouched: %q, %v", v, err)
		}
		if v, _ := c.Get(ctx, ref); v != "fresh" {
			t.Fatalf("composite read after write = %q, want fresh", v)
		}
	})
}

// Delete removes the value from both backends.
func TestCompositeDeleteRemovesBoth(t *testing.T) {
	withEnvFixture(t, func(ctx context.Context, f envFixture) {
		ref := credRef(t, "d1")
		f.legacy.Put(ctx, ref, "legacy")
		f.primary.Put(ctx, ref, "primary")
		c := &secretstore.Composite{Primary: f.primary, Legacy: f.legacy}
		if err := c.Delete(ctx, ref); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Get(ctx, ref); !errors.Is(err, secretstore.ErrNotFound) {
			t.Fatalf("deleted credential came back: %v", err)
		}
	})
}

// Migration copies every legacy value, reads each back equal, and is idempotent. Legacy rows are not removed.
func TestMigrateCopiesVerifiesAndIsIdempotent(t *testing.T) {
	withEnvFixture(t, func(ctx context.Context, f envFixture) {
		refs := []string{credRef(t, "m1"), credRef(t, "m2"), credRef(t, "m3")}
		for i, r := range refs {
			if err := f.legacy.Put(ctx, r, "legacy-"+string(rune('a'+i))); err != nil {
				t.Fatal(err)
			}
		}
		rep, err := secretstore.Migrate(ctx, f.primary, f.legacy)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Migrated) != 3 || len(rep.Failed) != 0 {
			t.Fatalf("first run: migrated %v, failed %v", rep.Migrated, rep.Failed)
		}
		for i, r := range refs {
			if v, err := f.primary.Get(ctx, r); err != nil || v != "legacy-"+string(rune('a'+i)) {
				t.Fatalf("primary %s = %q, %v", r, v, err)
			}
		}
		if v, err := f.legacy.Get(ctx, refs[0]); err != nil || v != "legacy-a" {
			t.Fatalf("legacy row must remain until retired: %q, %v", v, err)
		}
		rep2, err := secretstore.Migrate(ctx, f.primary, f.legacy)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep2.Migrated) != 0 || len(rep2.Skipped) != 3 {
			t.Fatalf("second run: migrated %v, skipped %v; want all skipped", rep2.Migrated, rep2.Skipped)
		}
	})
}

// A migration with a revoked primary key reports failures and migrates nothing.
func TestMigrateReportsFailuresWithRevokedKey(t *testing.T) {
	withEnvFixture(t, func(ctx context.Context, f envFixture) {
		ref := credRef(t, "mf1")
		f.legacy.Put(ctx, ref, "legacy")
		f.prov.Revoke(envRef)
		rep, err := secretstore.Migrate(ctx, f.primary, f.legacy)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Migrated) != 0 || len(rep.Failed) != 1 {
			t.Fatalf("revoked key: migrated %v, failed %v", rep.Migrated, rep.Failed)
		}
	})
}
