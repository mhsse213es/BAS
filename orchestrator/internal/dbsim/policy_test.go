package dbsim

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func testPolicy() Policy {
	return Policy{
		Source: "lab-policy-v1",
		Roles: map[string]RolePolicy{
			"app_reader": {
				Allow: map[string][]string{"public.orders": {"SELECT"}},
				Deny:  map[string][]string{"public.cards": {"ALL"}},
			},
			"app_writer": {
				Inherits: []string{"app_reader"},
				Allow:    map[string][]string{"public.orders": {"INSERT", "UPDATE"}},
			},
		},
	}
}

func TestDiffFlagsSeededExcessiveGrant(t *testing.T) {
	actual := []Grant{
		{Role: "app_reader", Object: "public.orders", Privilege: "SELECT"},
		{Role: "app_reader", Object: "public.orders", Privilege: "DELETE"}, // seeded excess
	}
	devs := Diff(testPolicy(), actual)
	if len(devs) != 1 {
		t.Fatalf("want exactly 1 deviation, got %d: %+v", len(devs), devs)
	}
	d := devs[0]
	if d.Kind != DeviationExcessive || d.Role != "app_reader" || d.Object != "public.orders" || d.Privilege != "DELETE" {
		t.Fatalf("unexpected deviation: %+v", d)
	}
	if d.PolicySource != "lab-policy-v1" {
		t.Fatalf("policy source not carried: %q", d.PolicySource)
	}
}

func TestDiffIncludesRoleInheritance(t *testing.T) {
	p := testPolicy()
	// app_writer inherits app_reader's SELECT: not a deviation.
	ok := Diff(p, []Grant{{Role: "app_writer", Object: "public.orders", Privilege: "SELECT"}})
	if len(ok) != 0 {
		t.Fatalf("inherited allow flagged: %+v", ok)
	}
	// app_writer inherits app_reader's DENY on cards: granting it is a deviation.
	bad := Diff(p, []Grant{{Role: "app_writer", Object: "public.cards", Privilege: "SELECT"}})
	if len(bad) != 1 || bad[0].Kind != DeviationDenied {
		t.Fatalf("inherited deny not enforced: %+v", bad)
	}
	if bad[0].DeniedVia != "app_reader" {
		t.Fatalf("DeniedVia = %q, want app_reader", bad[0].DeniedVia)
	}
	// Inheritance cycles must terminate.
	p.Roles["app_reader"] = RolePolicy{Inherits: []string{"app_writer"}, Allow: p.Roles["app_reader"].Allow, Deny: p.Roles["app_reader"].Deny}
	_ = Diff(p, []Grant{{Role: "app_writer", Object: "public.orders", Privilege: "DELETE"}})
}

func TestDiffUnknownRoleAndWildcards(t *testing.T) {
	p := Policy{Source: "s", Roles: map[string]RolePolicy{
		"admin": {Allow: map[string][]string{"*": {"ALL"}}},
		"etl":   {Allow: map[string][]string{"staging.*": {"select", "INSERT"}}},
	}}
	devs := Diff(p, []Grant{
		{Role: "admin", Object: "public.x", Privilege: "DELETE"},
		{Role: "etl", Object: "staging.t1", Privilege: "SELECT"},
		{Role: "etl", Object: "public.t1", Privilege: "SELECT"},
		{Role: "ghost", Object: "public.x", Privilege: "SELECT"},
	})
	if len(devs) != 2 {
		t.Fatalf("want 2 deviations, got %+v", devs)
	}
	kinds := map[string]DeviationKind{}
	for _, d := range devs {
		kinds[d.Role] = d.Kind
	}
	if kinds["etl"] != DeviationExcessive || kinds["ghost"] != DeviationUnknownRole {
		t.Fatalf("kinds = %+v", kinds)
	}
}

func TestDiffIsDeterministic(t *testing.T) {
	g := []Grant{
		{Role: "b", Object: "o2", Privilege: "X"}, {Role: "a", Object: "o1", Privilege: "Y"},
		{Role: "a", Object: "o1", Privilege: "X"},
	}
	p := Policy{Source: "s", Roles: map[string]RolePolicy{"a": {}, "b": {}}}
	a, b := Diff(p, g), Diff(p, g)
	if !reflect.DeepEqual(a, b) || a[0].Role != "a" || a[0].Privilege != "X" {
		t.Fatalf("not sorted/deterministic: %+v", a)
	}
}

// A Deviation is a read-only report: it must carry no field that can be
// executed (no revoke/remediation/SQL/command), in Go or in JSON.
func TestDiffNeverProducesRevokeAction(t *testing.T) {
	typ := reflect.TypeOf(Deviation{})
	banned := []string{"revoke", "remediat", "sql", "exec", "command", "statement", "fix", "action"}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type.Kind() != reflect.String {
			t.Fatalf("field %s is %s; Deviation fields must be plain strings", f.Name, f.Type)
		}
		name := strings.ToLower(f.Name + " " + f.Tag.Get("json"))
		for _, b := range banned {
			if strings.Contains(name, b) {
				t.Fatalf("Deviation field %s looks executable (%q)", f.Name, b)
			}
		}
	}
	devs := Diff(testPolicy(), []Grant{{Role: "app_reader", Object: "public.orders", Privilege: "DELETE"}})
	raw, _ := json.Marshal(devs)
	low := strings.ToLower(string(raw))
	for _, b := range []string{"revoke", "grant ", "drop ", "alter "} {
		if strings.Contains(low, b) {
			t.Fatalf("diff output contains %q: %s", b, raw)
		}
	}
}

func TestReportCarriesPolicySourceEvenWhenClean(t *testing.T) {
	r := Report(testPolicy(), nil)
	if r.PolicySource != "lab-policy-v1" || r.GrantsChecked != 0 || len(r.Deviations) != 0 {
		t.Fatalf("report = %+v", r)
	}
}
