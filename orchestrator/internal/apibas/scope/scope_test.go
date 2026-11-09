package scope

import "testing"

func TestAllowedBySegment(t *testing.T) {
	allowed := []string{"/api/orders", "/health"}
	cases := []struct {
		path string
		want bool
	}{
		{"/api/orders", true},
		{"/api/orders/", true},
		{"/api/orders/ORD-2001", true},
		{"/api/orders/ORD-2001/items?expand=kyc", true},
		{"/health", true},
		{"/api/orders-admin", false}, // shares a string prefix, not a segment prefix
		{"/api", false},              // shorter than the allowed prefix
		{"/", false},
		{"/api/customers", false},
		{"/API/orders", false}, // case-sensitive
		{"api/orders", false},  // not rooted
	}
	for _, c := range cases {
		if got := Allowed(allowed, c.path); got != c.want {
			t.Errorf("Allowed(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestAllowedRefusesTraversalAndOddForms(t *testing.T) {
	allowed := []string{"/api/orders"}
	for _, p := range []string{
		"/api/orders/../admin",
		"/api/orders/./x",
		"/api/orders/%2e%2e/admin",
		"/api/orders/%2E%2E/admin",
		"/api/orders/%2e/x",
		"/api/orders/a%2Fb",
		"/api/orders\\..\\admin",
		"/api/orders//x",
		"/api/orders/%zz",
		"/api/orders/\x00",
	} {
		if Allowed(allowed, p) {
			t.Errorf("Allowed(%q) = true, want false", p)
		}
	}
}

func TestEmptyListAllowsNothing(t *testing.T) {
	if Allowed(nil, "/api/orders") || Allowed([]string{}, "/") {
		t.Fatal("an empty allow-list allowed a path")
	}
}

func TestValidPrefix(t *testing.T) {
	for p, want := range map[string]bool{
		"/api/orders": true, "/api": true, "/": false, "": false, "api": false,
		"/api/orders?x=1": false, "/api/../x": false, "/api/orders#f": false,
	} {
		if got := ValidPrefix(p); got != want {
			t.Errorf("ValidPrefix(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestStaticPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"/api/orders/{object}":           "/api/orders",
		"/api/orders/{object}/items":     "/api/orders",
		"/api/orders?expand=kyc":         "/api/orders",
		"/api/orders/ORD-2001":           "/api/orders/ORD-2001",
		"{object}":                       "",
		"/{object}":                      "/",
		"/api/orders/ORD-{object}":       "/api/orders/ORD-",
		"/api/orders/{object}?x={other}": "/api/orders",
	} {
		if got := StaticPrefix(in); got != want {
			t.Errorf("StaticPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}
