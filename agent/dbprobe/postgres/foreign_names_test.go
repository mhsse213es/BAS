package postgres

import (
	"strings"
	"testing"
)

// Test 11 counts role names other than the probe's own and the built-in pg_* roles.
// The probe must exclude the current role and report counts only through its rows.
func TestForeignRoleNamesExcludeOwnAndBuiltInRoles(t *testing.T) {
	sql, args, err := probeSQL("read_foreign_role_names", nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 0 {
		t.Errorf("fixed probe must take no bind args, got %v", args)
	}
	for _, want := range []string{"pg_roles", "rolname <> current_user", `'pg\_%'`} {
		if !strings.Contains(sql, want) {
			t.Errorf("sql missing %q: %s", want, sql)
		}
	}
	if strings.Contains(strings.ToUpper(sql), "ROLCANLOGIN") || strings.Contains(strings.ToUpper(sql), "ROLSUPER") {
		t.Errorf("sql must not select role attributes: %s", sql)
	}
}
