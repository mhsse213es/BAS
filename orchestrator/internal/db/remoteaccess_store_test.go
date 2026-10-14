package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/remoteaccess"
)

func TestInsertAndGetRemoteAccessImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		imp := &remoteaccess.RemoteAccessImport{
			ID:         "ra-roundtrip-1",
			SourceType: "manual",
			Tunnels: []remoteaccess.VPNTunnel{
				{CanonicalID: "vpn-1", FromZone: "branch", ToZone: "datacenter", State: remoteaccess.TunnelUp},
			},
			Transits: []remoteaccess.MandatoryTransit{
				{CanonicalID: "mt-1", FromZone: "corporate", ToZone: "production", ViaZone: "bastion"},
			},
		}
		if err := db.InsertRemoteAccessImport(context.Background(), pool, imp); err != nil {
			t.Fatalf("insert: %v", err)
		}
		got, err := db.GetRemoteAccessImport(context.Background(), pool, imp.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if len(got.Tunnels) != 1 || got.Tunnels[0].CanonicalID != "vpn-1" {
			t.Fatalf("got.Tunnels = %v, want one tunnel vpn-1", got.Tunnels)
		}
		if len(got.Transits) != 1 || got.Transits[0].CanonicalID != "mt-1" {
			t.Fatalf("got.Transits = %v, want one transit mt-1", got.Transits)
		}
	})
}

func TestGetRemoteAccessImport_NotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetRemoteAccessImport(context.Background(), pool, "does-not-exist")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("err = %v, want errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}

func TestListRemoteAccessImports_NewestFirst(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		first := &remoteaccess.RemoteAccessImport{ID: "ra-list-1", SourceType: "manual"}
		second := &remoteaccess.RemoteAccessImport{ID: "ra-list-2", SourceType: "manual"}
		if err := db.InsertRemoteAccessImport(context.Background(), pool, first); err != nil {
			t.Fatalf("insert first: %v", err)
		}
		if err := db.InsertRemoteAccessImport(context.Background(), pool, second); err != nil {
			t.Fatalf("insert second: %v", err)
		}
		list, err := db.ListRemoteAccessImports(context.Background(), pool, 10)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list) < 2 {
			t.Fatalf("list = %v, want at least 2 entries", list)
		}
	})
}
