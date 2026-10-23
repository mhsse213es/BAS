package property

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/grade"
)

func reserved(opID, role string) func(*TemplateCtx) {
	return func(c *TemplateCtx) { c.ReservedRoles = map[string]string{opID: role} }
}

func TestRoleTemplatesDetectToyBFLA(t *testing.T) {
	// A write reserved for admin: the oracle is a state change.
	ty, srv := newToy("role")
	defer srv.Close()
	tpls := templatesFor(t, "P-ROLE-1", "archive", reserved("archive", "admin"))
	// alice (member) and bob (member), carol (checker): three lower-role owners.
	if len(tpls) != 4 {
		t.Fatalf("want 4 templates (member x2, checker x2), got %d", len(tpls))
	}
	expect(t, ty, srv, tpls, grade.FAIL)

	// A read reserved for admin: the oracle is "accepted twice".
	reads := templatesFor(t, "P-ROLE-1", "reports", reserved("reports", "admin"))
	expect(t, ty, srv, reads, grade.FAIL)

	ok, srvOK := newToy()
	defer srvOK.Close()
	expect(t, ok, srvOK, tpls, grade.PASS)
	expect(t, ok, srvOK, reads, grade.PASS)
}

func TestRoleTemplatesNeedDeclarations(t *testing.T) {
	if got := templatesFor(t, "P-ROLE-1", "archive", nil); len(got) != 0 {
		t.Fatalf("no reserved declaration must yield no templates, got %d", len(got))
	}
	if got := templatesFor(t, "P-ROLE-1", "archive", reserved("archive", "nonexistent")); len(got) != 0 {
		t.Fatal("unknown role must yield no templates")
	}
	// The top role is never an attacker for itself.
	for _, tp := range templatesFor(t, "P-ROLE-1", "archive", reserved("archive", "admin")) {
		if tp.Params["role"] == "admin" {
			t.Fatal("admin cannot be the lower-role attacker")
		}
	}
	m := toyModel()
	m.Roles = []string{"only"}
	var p Property
	for _, c := range All() {
		if c.ID() == "P-ROLE-1" {
			p = c
		}
	}
	if p.Applies(modelOp(t, m, "archive"), m) {
		t.Fatal("a single-role model has no lower role")
	}
}

func TestVersionDifferentialDetectsToyLegacyRoute(t *testing.T) {
	ty, srv := newToy("read-v1")
	defer srv.Close()
	v1 := templatesFor(t, "P-ROLE-2", "getV1", nil)
	v2 := templatesFor(t, "P-ROLE-2", "getV2", nil)
	if len(v1) != 1 || len(v2) != 1 {
		t.Fatalf("want one template per route, got %d and %d", len(v1), len(v2))
	}
	if v1[0].Params["group"] == "" || v1[0].Params["group"] != v2[0].Params["group"] {
		t.Fatalf("routes must share a group: %q vs %q", v1[0].Params["group"], v2[0].Params["group"])
	}
	// Differential: the legacy route leaks, the current one does not.
	expect(t, ty, srv, v1, grade.FAIL)
	expect(t, ty, srv, v2, grade.PASS)

	ok, srvOK := newToy()
	defer srvOK.Close()
	expect(t, ok, srvOK, v1, grade.PASS)
	expect(t, ok, srvOK, v2, grade.PASS)
}

func TestRouteKeyNormalization(t *testing.T) {
	m := toyModel()
	a, b := modelOp(t, m, "getV1"), modelOp(t, m, "getV2")
	if routeKey(a) != routeKey(b) {
		t.Fatalf("%q != %q", routeKey(a), routeKey(b))
	}
	if routeKey(modelOp(t, m, "reports")) == routeKey(a) {
		t.Fatal("unrelated routes must not share a key")
	}
	if len(peers(modelOp(t, m, "patchV2"), m)) != 0 {
		t.Fatal("patchV2 has no peer")
	}
}
