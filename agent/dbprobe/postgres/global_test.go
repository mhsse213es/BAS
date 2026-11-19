package postgres

import "testing"

func TestStrictGlobalGrantsKeepsEveryRowOrRefuses(t *testing.T) {
	ok, err := strictGlobalGrants([][]any{{"dbsim_lab", "cluster", "CREATEROLE"}, {"dbsim_lab", "database:dbsim", "CREATE"}})
	if err != nil || len(ok) != 2 || ok[0].Privilege != "CREATEROLE" || ok[1].Scope != "database:dbsim" {
		t.Fatalf("valid rows: %v %+v", err, ok)
	}
	if _, err := strictGlobalGrants([][]any{{"dbsim_lab", "cluster"}}); err == nil {
		t.Error("a short row was dropped instead of refused")
	}
	if _, err := strictGlobalGrants([][]any{{nil, "cluster", "SUPERUSER"}}); err == nil {
		t.Error("a NULL role was accepted instead of refused")
	}
}

func TestStrictMembershipsKeepsEveryRowOrRefuses(t *testing.T) {
	ok, err := strictMemberships([][]any{{"bas_dbsim_parent", "dbsim_lab", true}})
	if err != nil || len(ok) != 1 || ok[0].Role != "bas_dbsim_parent" || ok[0].Member != "dbsim_lab" || !ok[0].Inherit {
		t.Fatalf("valid row: %v %+v", err, ok)
	}
	if _, err := strictMemberships([][]any{{"bas_dbsim_parent", "dbsim_lab", "t"}}); err == nil {
		t.Error("a text inherit flag was accepted instead of refused")
	}
}
