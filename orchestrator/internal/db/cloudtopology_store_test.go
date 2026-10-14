package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudtopology"
	"github.com/audspect/bas/internal/db"
)

func testCloudTopologyImport(id string) *cloudtopology.CloudTopologyImport {
	return &cloudtopology.CloudTopologyImport{
		ID:         id,
		SourceType: "manual",
		Networks:   []cloudtopology.CloudNetwork{{CanonicalID: "vpc-1", CIDRBlocks: []string{"10.0.0.0/16"}}},
		Subnets:    []cloudtopology.CloudSubnet{{CanonicalID: "subnet-1", NetworkID: "vpc-1", CIDRBlock: "10.0.1.0/24"}},
		Groups:     []cloudtopology.SecurityGroup{{CanonicalID: "sg-1", NetworkID: "vpc-1", Scope: cloudtopology.ScopeNetwork}},
		Rules: []cloudtopology.SecurityGroupRule{
			{ID: "r1", GroupID: "sg-1", Order: 10, Direction: cloudtopology.DirectionOutbound, Action: cloudtopology.ActionAllow, Protocol: "tcp", PortRange: "443", CIDR: "0.0.0.0/0"},
		},
		Routes:   []cloudtopology.RouteTableEntry{{ID: "rt-1", SubnetID: "subnet-1", DestinationCIDR: "0.0.0.0/0", Target: cloudtopology.TargetInternetGateway}},
		Peerings: nil,
	}
}

func TestCloudTopologyImport_InsertGetList_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		imp := testCloudTopologyImport("ctimp-roundtrip-1")
		if err := db.InsertCloudTopologyImport(ctx, pool, imp); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := db.GetCloudTopologyImport(ctx, pool, imp.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if len(got.Subnets) != 1 || got.Subnets[0].CanonicalID != "subnet-1" {
			t.Fatalf("Subnets round-tripped as %v", got.Subnets)
		}
		if len(got.Rules) != 1 || got.Rules[0].ID != "r1" {
			t.Fatalf("Rules round-tripped as %v", got.Rules)
		}

		list, err := db.ListCloudTopologyImports(ctx, pool, 10)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		found := false
		for _, l := range list {
			if l.ID == imp.ID {
				found = true
			}
		}
		if !found {
			t.Fatal("inserted import not present in list")
		}
	})
}

func TestGetCloudTopologyImport_NotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetCloudTopologyImport(context.Background(), pool, "does-not-exist")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("got %v, want an error satisfying errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}
