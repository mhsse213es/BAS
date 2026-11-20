package dbbuild

import (
	"testing"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/scenario"
)

// A fixture step seeds with the target's privileged credential; a non-fixture
// step never carries one, so existing specs are unchanged.
func TestSeedCredentialForFixtureStepsOnly(t *testing.T) {
	tgt := dbsim.Target{ID: "lab-db", CredentialRef: "dbcred:lab-pg-ro", SeedCredentialRef: "dbcred:lab-pg-admin"}
	if got := seedCredentialFor(scenario.Step{DBFixture: "authz-restricted"}, tgt); got != "dbcred:lab-pg-admin" {
		t.Fatalf("fixture step seed credential = %q, want dbcred:lab-pg-admin", got)
	}
	if got := seedCredentialFor(scenario.Step{}, tgt); got != "" {
		t.Fatalf("non-fixture step carried seed credential %q", got)
	}
}
