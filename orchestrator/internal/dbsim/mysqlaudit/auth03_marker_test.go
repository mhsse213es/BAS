package mysqlaudit

import (
	"strings"
	"testing"
)

func TestAuthMarkerIsRunSpecificAndSafe(t *testing.T) {
	m, err := authMarker("r1-abc")
	if err != nil {
		t.Fatalf("authMarker: %v", err)
	}
	if m != "dbsim:auth-r1-abc" {
		t.Errorf("marker = %q", m)
	}
	for _, bad := range []string{"", "a b", "x*/ DROP", "a'b", "a;b", strings.Repeat("a", 65)} {
		if _, err := authMarker(bad); err == nil {
			t.Errorf("run id %q must be refused (it could break the SQL comment or the audit match)", bad)
		}
	}
}
