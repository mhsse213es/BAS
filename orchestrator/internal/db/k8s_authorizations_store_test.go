package db

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/audspect/bas/internal/k8sscenario"
)

// TestK8sAuthorizationStore_AtomicWithAudit needs TEST_DATABASE_URL; it is skipped otherwise. It runs against a real
// PostgreSQL and proves: a record and its audit row are written together; a failed audit write leaves no record and no
// change; a customer reference must name an active tenant; a revoke applies once; and the database refuses an empty
// scope and an unregistered cluster.
func TestK8sAuthorizationStore_AtomicWithAudit(t *testing.T) {
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
	if err := EnsureSchema(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := EnsureK8sClusterSchema(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := EnsureK8sAuthorizationSchema(ctx, pool); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Format("150405.000000")
	clusterID := "k8sc-auth-" + stamp
	tenantID := "tenant-auth-" + stamp
	suspendedID := "tenant-susp-" + stamp
	clusters := NewK8sClusterStore(pool)
	store := NewK8sAuthorizationStore(pool)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM k8s_customer_authorizations WHERE cluster_id = $1`, clusterID)
		_, _ = pool.Exec(ctx, `DELETE FROM k8s_clusters WHERE id = $1`, clusterID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id IN ($1, $2)`, tenantID, suspendedID)
		_, _ = pool.Exec(ctx, `DELETE FROM audit_logs WHERE resource LIKE $1`, "%"+stamp+"%")
	})
	if err := clusters.Insert(ctx, k8sscenario.ClusterRecord{ID: clusterID, DisplayName: "auth-test-" + stamp,
		ServerURL: "https://auth-test-" + stamp + ".example", Class: k8sscenario.ClassNonProduction}); err != nil {
		t.Fatal(err)
	}
	for id, status := range map[string]string{tenantID: "active", suspendedID: "suspended"} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name, slug, status) VALUES ($1, $1, $1, $2)`, id, status); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now().UTC().Truncate(time.Second)
	newRec := func(id, tenant string) k8sscenario.CustomerAuthorization {
		return k8sscenario.CustomerAuthorization{ID: id, ClusterID: clusterID, CustomerRef: tenant,
			AuthorizedBy: "admin-1", AuthorizedAt: now, ExpiresAt: now.Add(time.Hour),
			Scenarios: []string{"configmap-patch-labelled"}, Namespaces: []string{"bas-sandbox"}}
	}
	event := func(kind, id string) k8sscenario.Event {
		return k8sscenario.AuthorizationEvent(kind, newRec(id, tenantID), "admin-1", "auth-test")
	}
	badEvent := func(id string) k8sscenario.Event {
		ev := event("created", id)
		ev.Fields["poison"] = "bad\x00value" // jsonb rejects a NUL escape, so the audit insert fails
		return ev
	}
	rowExists := func(id string) bool {
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM k8s_customer_authorizations WHERE id = $1`, id).Scan(&n)
		return n == 1
	}
	auditCount := func(action, id string) int {
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = $1 AND resource = $2`, action, id).Scan(&n)
		return n
	}

	// 1. The record and its creation event are written together.
	okID := "k8sa-ok-" + stamp
	if err := store.InsertWithAudit(ctx, newRec(okID, tenantID), event("created", okID)); err != nil {
		t.Fatalf("insert with audit: %v", err)
	}
	if !rowExists(okID) || auditCount("k8s.authorization.created", okID) != 1 {
		t.Fatalf("the record and its creation event must both exist")
	}

	// 2. A failed audit write leaves no record at all.
	failID := "k8sa-fail-" + stamp
	if err := store.InsertWithAudit(ctx, newRec(failID, tenantID), badEvent(failID)); err == nil {
		t.Fatal("an audit write that fails must fail the creation")
	}
	if rowExists(failID) {
		t.Fatal("a record must not exist when its creation event could not be written")
	}

	// 3. An unknown or suspended tenant stores nothing.
	for _, tenant := range []string{"tenant-missing-" + stamp, suspendedID} {
		id := "k8sa-ten-" + stamp + tenant[:4]
		if err := store.InsertWithAudit(ctx, newRec(id, tenant), event("created", id)); !errors.Is(err, ErrCustomerNotFound) {
			t.Errorf("tenant %q: want ErrCustomerNotFound, got %v", tenant, err)
		}
		if rowExists(id) || auditCount("k8s.authorization.created", id) != 0 {
			t.Errorf("tenant %q: nothing may be stored", tenant)
		}
	}

	// 4. The database refuses an empty scope and an unregistered cluster, whatever the code says.
	empty := newRec("k8sa-empty-"+stamp, tenantID)
	empty.Namespaces = []string{}
	if err := store.InsertWithAudit(ctx, empty, event("created", empty.ID)); err == nil {
		t.Error("an empty namespace list must be refused by the database")
	}
	orphan := newRec("k8sa-orphan-"+stamp, tenantID)
	orphan.ClusterID = "k8sc-nope-" + stamp
	if err := store.InsertWithAudit(ctx, orphan, event("created", orphan.ID)); err == nil {
		t.Error("a record for an unregistered cluster must be refused by the database")
	}

	// 5. A revoke applies once and writes its event with it.
	if err := store.RevokeWithAudit(ctx, okID, "admin-2", now, event("revoked", okID)); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if err := store.RevokeWithAudit(ctx, okID, "admin-3", now, event("revoked", okID)); !errors.Is(err, ErrAuthorizationRevoked) {
		t.Errorf("a second revoke must report already revoked, got %v", err)
	}
	if err := store.RevokeWithAudit(ctx, "k8sa-missing-"+stamp, "admin-2", now, event("revoked", "k8sa-missing-"+stamp)); !errors.Is(err, ErrAuthorizationNotFound) {
		t.Errorf("an unknown record must report not found, got %v", err)
	}
	if got, _, _ := store.Get(ctx, okID); got.RevokedBy != "admin-2" {
		t.Errorf("the first revoker must be the one recorded: %q", got.RevokedBy)
	}
	if auditCount("k8s.authorization.revoked", okID) != 1 {
		t.Error("exactly one revoke event must be written")
	}

	// 6. A failed revoke audit leaves the record active.
	secondID := "k8sa-rev-" + stamp
	if err := store.InsertWithAudit(ctx, newRec(secondID, tenantID), event("created", secondID)); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeWithAudit(ctx, secondID, "admin-2", now, badEvent(secondID)); err == nil {
		t.Fatal("a revoke whose audit write fails must fail")
	}
	if got, _, _ := store.Get(ctx, secondID); got.RevokedAt != nil {
		t.Error("a revoke whose audit could not be written must leave the record active")
	}

	list, err := store.List(ctx, clusterID)
	if err != nil || len(list) != 2 {
		t.Errorf("list for the cluster: want 2 records, got %d (err %v)", len(list), err)
	}
}
