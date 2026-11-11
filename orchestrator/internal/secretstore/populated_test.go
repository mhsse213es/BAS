package secretstore_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/envelope"
	"github.com/audspect/bas/internal/kms"
	"github.com/audspect/bas/internal/kms/memprovider"
	"github.com/audspect/bas/internal/secretstore"
	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

// populatedValues returns a set of credentials that look like real ones: varied lengths, punctuation and unicode.
func populatedValues(n int) map[string]string {
	out := make(map[string]string, n)
	for i := 0; i < n; i++ {
		ref, _ := secretstore.MakeRef("siem_configs", fmt.Sprintf("row%03d", i), "token")
		v := fmt.Sprintf("tok-%03d-%s", i, strings.Repeat("x", (i*37)%4096))
		if i%7 == 0 {
			v = fmt.Sprintf("p@ss'w\"rd;--%d ünïcødé", i)
		}
		out[ref] = v
	}
	return out
}

// This is a component-level simulation of a populated host, not a real install. It exercises the data path: a database
// with existing legacy credentials, the migration on it, and a restore of the envelope table into a clean database
// that uses the same customer KEK. A real install-and-restore on a host needs the signed bundle and is still open.
func TestPopulatedHostMigrationAndCleanRestore(t *testing.T) {
	ctx := context.Background()
	values := populatedValues(60)
	legacyKey := newKeyText(t)
	kek := kms.KeyRef("customer-kek")

	// The customer's provider persists across hosts. Its KEK is created once.
	vaultStand := memprovider.New()
	if err := vaultStand.CreateKey(kek); err != nil {
		t.Fatal(err)
	}

	srcDB := testutil.NewTestDB(t)
	srcDB.RunWithPool(t, func(src *pgxpool.Pool) {
		if err := db.EnsureSecretStoreSchema(ctx, src); err != nil {
			t.Fatal(err)
		}
		legacy, err := secretstore.NewPGStore(src, legacyKey)
		if err != nil {
			t.Fatal(err)
		}
		for ref, v := range values {
			if err := legacy.Put(ctx, ref, v); err != nil {
				t.Fatal(err)
			}
		}

		// Step 1: migrate the populated host.
		mgr := envelope.New(vaultStand, envelope.Config{})
		primary, err := secretstore.NewEnvelopeStore(src, mgr, kek)
		if err != nil {
			t.Fatal(err)
		}
		rep, err := secretstore.Migrate(ctx, primary, legacy)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Migrated) != len(values) || len(rep.Failed) != 0 {
			t.Fatalf("migration: migrated %d of %d, failed %v", len(rep.Migrated), len(values), rep.Failed)
		}

		// Step 2: after migration, every value reads through the envelope alone. The legacy key is not needed.
		composite := &secretstore.Composite{Primary: primary, Legacy: secretstore.NoLegacy{}}
		for ref, want := range values {
			got, err := composite.Get(ctx, ref)
			if err != nil || got != want {
				t.Fatalf("after migration, %s: got %q, %v", ref, got, err)
			}
		}

		// Step 3: restore the envelope table into a clean database (a new host). Only the envelope rows move;
		// the legacy key does not.
		type row struct {
			ref  string
			blob []byte
		}
		var rows []row
		rr, err := src.Query(ctx, `SELECT ref, blob FROM credential_secrets_envelope ORDER BY ref`)
		if err != nil {
			t.Fatal(err)
		}
		for rr.Next() {
			var r row
			if err := rr.Scan(&r.ref, &r.blob); err != nil {
				t.Fatal(err)
			}
			rows = append(rows, r)
		}
		rr.Close()
		if len(rows) != len(values) {
			t.Fatalf("envelope rows = %d, want %d", len(rows), len(values))
		}

		cleanDB := testutil.NewTestDB(t)
		cleanDB.RunWithPool(t, func(dst *pgxpool.Pool) {
			if err := db.EnsureSecretStoreSchema(ctx, dst); err != nil {
				t.Fatal(err)
			}
			for _, r := range rows {
				if _, err := dst.Exec(ctx, `INSERT INTO credential_secrets_envelope (ref, blob) VALUES ($1, $2)`, r.ref, r.blob); err != nil {
					t.Fatal(err)
				}
			}

			// Step 4: the clean host reads everything with the same customer KEK.
			restored, err := secretstore.NewEnvelopeStore(dst, envelope.New(vaultStand, envelope.Config{}), kek)
			if err != nil {
				t.Fatal(err)
			}
			for ref, want := range values {
				got, err := restored.Get(ctx, ref)
				if err != nil || got != want {
					t.Fatalf("restored host, %s: got %q, %v", ref, got, err)
				}
			}

			// Step 5: wrong-key case. A host whose provider holds a different KEK under the same name reads nothing,
			// and no value is returned in any form.
			wrongStand := memprovider.New()
			if err := wrongStand.CreateKey(kek); err != nil {
				t.Fatal(err)
			}
			wrong, err := secretstore.NewEnvelopeStore(dst, envelope.New(wrongStand, envelope.Config{}), kek)
			if err != nil {
				t.Fatal(err)
			}
			for ref := range values {
				got, err := wrong.Get(ctx, ref)
				if err == nil || got != "" {
					t.Fatalf("wrong KEK, %s: returned %q, err %v; want an error and no value", ref, got, err)
				}
			}
		})
	})
}
