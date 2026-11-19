package mysql

import (
	"strings"
	"testing"
)

// Test 11 counts account names other than the probe's own and the built-in mysql.*
// accounts. The probe selects names but reports only the row count.
func TestForeignAccountNamesExcludeOwnAndBuiltInAccounts(t *testing.T) {
	sql, args, err := probeSQL("read_foreign_role_names", nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 0 {
		t.Errorf("fixed probe must take no bind args, got %v", args)
	}
	for _, want := range []string{"mysql.user", "CURRENT_USER()", "'mysql.%'"} {
		if !strings.Contains(sql, want) {
			t.Errorf("sql missing %q: %s", want, sql)
		}
	}
}
