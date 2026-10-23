//go:build dbsim_integration

package postgres

import (
	"context"
	"errors"
	"testing"

	"audspect/agent/dbprobe"
	"audspect/agent/dbprobe/fixtures"
)

// A pre-existing schema of the same name must make Seed fail with
// ErrFixtureNotCreated and must survive untouched (no DROP ... CASCADE).
func TestPGSeedCollisionLeavesPreexistingSchemaAlone(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeLab)
	ctx := context.Background()
	if err := a.s.Exec(ctx, `CREATE SCHEMA "dbsim_itcol"`); err != nil {
		t.Fatal(err)
	}
	defer a.s.Exec(ctx, `DROP SCHEMA IF EXISTS "dbsim_itcol" CASCADE`)
	if err := a.s.Exec(ctx, `CREATE TABLE "dbsim_itcol"."keep" (id int)`); err != nil {
		t.Fatal(err)
	}
	spec, _ := fixtures.Lookup("accounts")
	err := a.Seed(ctx, dbprobe.Fixture{ID: "itcol", Kind: "accounts", Tables: spec.Tables})
	if !errors.Is(err, dbprobe.ErrFixtureNotCreated) {
		t.Fatalf("err = %v, want ErrFixtureNotCreated", err)
	}
	objs, err := a.InspectFixture(ctx, dbprobe.Fixture{ID: "itcol"})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, o := range objs {
		found[o] = true
	}
	if !found["schema:dbsim_itcol"] || !found["table:dbsim_itcol.keep"] {
		t.Fatalf("pre-existing objects were disturbed: %v", objs)
	}
}

// The seeded schema must be visible to the lab account's inspection: this is
// the premise of fixtures.Seed's post-seed visibility check.
func TestPGSeededSchemaIsVisibleToInspection(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeLab)
	spec, _ := fixtures.Lookup("empty")
	_, err := fixtures.WithFixture(context.Background(), a, spec, func(fx dbprobe.Fixture) error {
		objs, err := a.InspectFixture(context.Background(), fx)
		if err != nil {
			return err
		}
		for _, o := range objs {
			if o == "schema:"+fixtures.SchemaName(fx.ID) {
				return nil
			}
		}
		t.Errorf("schema not visible: %v", objs)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
