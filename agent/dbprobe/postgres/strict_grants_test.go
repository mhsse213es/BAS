package postgres

import "testing"

func TestStrictGrantsKeepsEveryRowOrRefuses(t *testing.T) {
	ok, err := strictGrants([][]any{{"app", "public.accounts", "SELECT", true}})
	if err != nil || len(ok) != 1 || ok[0].Privilege != "SELECT" || !ok[0].GrantOption {
		t.Fatalf("valid row: %v %+v", err, ok)
	}
	if _, err := strictGrants([][]any{{"app", "public.accounts", "SELECT"}}); err == nil {
		t.Error("a row without the grant-option column was accepted")
	}
	if _, err := strictGrants([][]any{{"app", "public.accounts", "SELECT", "YES"}}); err == nil {
		t.Error("a text grant option was accepted instead of refused")
	}
	if _, err := strictGrants([][]any{{"app", nil, "SELECT", false}}); err == nil {
		t.Error("a NULL object was accepted instead of refused")
	}
}
