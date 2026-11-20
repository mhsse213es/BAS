package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
)

var errFakeRoleMissing = errors.New(`role does not exist`)

// A fixture without an owner role (the "empty" kind) must clean up cleanly: a
// bare REVOKE of a role that does not exist fails the whole cleanup.
func TestCleanupDoesNotRevokeMissingRoles(t *testing.T) {
	var sent []string
	admin := &fakeSession{execFn: func(sql string) error {
		sent = append(sent, sql)
		if strings.HasPrefix(sql, "REVOKE ") {
			return errFakeRoleMissing
		}
		return nil
	}}
	a := &Adapter{s: admin, mode: dbprobe.ModeLab}
	if err := a.BindFixture(emptyFixture()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Cleanup(context.Background(), emptyFixture()); err != nil {
		t.Fatalf("cleanup of a fixture with no owner role must succeed: %v", err)
	}
	for _, s := range sent {
		if strings.HasPrefix(s, "REVOKE ") {
			t.Fatalf("bare REVOKE sent for a role that may not exist: %q", s)
		}
	}
}
