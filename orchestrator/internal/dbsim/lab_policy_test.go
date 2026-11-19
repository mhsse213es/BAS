package dbsim

import (
	"os"
	"testing"
)

// The shipped lab policy must parse and name its source.
func TestLabPolicyFileParses(t *testing.T) {
	b, err := os.ReadFile("../../../lab/dbsim/policy-lab.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := PolicyFromJSON(b)
	if err != nil {
		t.Fatalf("lab policy: %v", err)
	}
	if p.Source == "" || len(p.Roles) == 0 {
		t.Fatalf("lab policy incomplete: %+v", p)
	}
}

// Preview: the staging catalog output, from the psql run on 2026-11-19, through the lab policy.
func TestLabPolicyPreviewOnStagingCatalog(t *testing.T) {
	b, _ := os.ReadFile("../../../lab/dbsim/policy-lab.json")
	p, _ := PolicyFromJSON(b)
	globals := []GlobalGrant{
		{"PUBLIC", "database:dbsim", "CONNECT"}, {"PUBLIC", "database:dbsim", "TEMPORARY"},
		{"dbsim_lab", "cluster", "CREATEROLE"}, {"dbsim_lab", "database:dbsim", "CREATE"},
		{"postgres", "cluster", "BYPASSRLS"}, {"postgres", "cluster", "CREATEDB"}, {"postgres", "cluster", "CREATEROLE"},
		{"postgres", "cluster", "SUPERUSER"}, {"postgres", "database:dbsim", "CONNECT"}, {"postgres", "database:dbsim", "CREATE"},
		{"postgres", "database:dbsim", "TEMPORARY"},
	}
	for _, d := range DiffGlobal(p, globals) {
		t.Logf("GLOBAL %s %s %s %s", d.Kind, d.Role, d.Object, d.Privilege)
	}
	for _, d := range DiffMemberships(p, []Membership{{Role: "bas_dbsim_parent", Member: "dbsim_lab", Inherit: true}}) {
		t.Logf("MEMBERSHIP %s %s granted %s", d.Kind, d.Role, d.Object)
	}
}
