package db

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/audspect/bas/internal/k8sscenario"
)

// TestK8sClusterStore_IdentityPinsThenRefusesChange needs TEST_DATABASE_URL; it is skipped otherwise.
func TestK8sClusterStore_IdentityPinsThenRefusesChange(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := EnsureK8sClusterSchema(ctx, pool); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Format("150405.000000")
	id := "k8sc-id-" + stamp
	store := NewK8sClusterStore(pool)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM k8s_clusters WHERE id = $1`, id) })

	rec := k8sscenario.ClusterRecord{ID: id, DisplayName: "id-test-" + stamp,
		ServerURL: "https://id-test-" + stamp + ".example", Class: k8sscenario.ClassLab}
	if err := store.Insert(ctx, rec); err != nil {
		t.Fatal(err)
	}
	pin := k8sscenario.ClusterRecord{Version: "v1.30.4", CAFingerprint: "ca-a", SPKIHash: "spki-a", VerifiedAt: time.Now().UTC()}
	if err := store.UpdateIdentity(ctx, id, pin); err != nil {
		t.Fatalf("first pin: %v", err)
	}
	if err := store.UpdateIdentity(ctx, id, pin); err != nil {
		t.Fatalf("same identity must be accepted: %v", err)
	}
	changed := pin
	changed.SPKIHash = "spki-b"
	if err := store.UpdateIdentity(ctx, id, changed); !errors.Is(err, ErrK8sIdentityChanged) {
		t.Fatalf("changed identity: want ErrK8sIdentityChanged, got %v", err)
	}
	got, found, err := store.Get(ctx, id)
	if err != nil || !found {
		t.Fatalf("get: %v %v", found, err)
	}
	if got.SPKIHash != "spki-a" || got.Version != "v1.30.4" || got.VerifiedAt.IsZero() {
		t.Errorf("stored identity was overwritten: %+v", got)
	}
}
