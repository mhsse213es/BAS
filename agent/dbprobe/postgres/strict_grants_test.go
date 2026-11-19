package postgres

import "testing"

func TestStrictGrantsKeepsEveryRowOrRefuses(t *testing.T) {
	ok, err := strictGrants([][]any{{"app", "public.accounts", "SELECT"}})
	if err != nil || len(ok) != 1 || ok[0].Privilege != "SELECT" {
		t.Fatalf("valid row: %v %+v", err, ok)
	}
	if _, err := strictGrants([][]any{{"app", "public.accounts"}}); err == nil {
		t.Error("a short row was dropped instead of refused")
	}
	if _, err := strictGrants([][]any{{"app", nil, "SELECT"}}); err == nil {
		t.Error("a NULL object was accepted instead of refused")
	}
}
