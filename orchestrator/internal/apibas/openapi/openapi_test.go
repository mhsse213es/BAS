package openapi

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func load(t *testing.T) *Inventory {
	t.Helper()
	data, err := os.ReadFile("testdata/shop.yaml")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := Import(data)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	return inv
}

func op(t *testing.T, inv *Inventory, key string) Operation {
	t.Helper()
	for _, o := range inv.Operations {
		if o.Key() == key {
			return o
		}
	}
	t.Fatalf("operation %q not in the inventory", key)
	return Operation{}
}

func hasClass(o Operation, c Class) bool {
	for _, x := range o.Classes {
		if x == c {
			return true
		}
	}
	return false
}

func TestImportReadsDocumentFacts(t *testing.T) {
	inv := load(t)
	if inv.Title != "Shop API" || inv.OpenAPIVersion != "3.0.3" || len(inv.Servers) != 1 {
		t.Errorf("document facts: %q %q %v", inv.Title, inv.OpenAPIVersion, inv.Servers)
	}
	if len(inv.Operations) != 11 {
		t.Errorf("%d operations, want 11", len(inv.Operations))
	}
}

func TestPathLevelParameterAndRefAreResolved(t *testing.T) {
	o := op(t, load(t), "GET /v2/orders/{orderId}")
	if len(o.PathParams) != 1 || o.PathParams[0] != "orderId" {
		t.Errorf("path params %v, want [orderId] from the path-level $ref", o.PathParams)
	}
	// The response schema is followed through $ref, into nested objects and array items.
	for _, want := range []string{"id", "total", "customer", "email", "national_id", "items", "sku"} {
		if !contains(o.ResponseFields, want) {
			t.Errorf("response fields %v lack %q", o.ResponseFields, want)
		}
	}
}

func TestEffectiveAuthentication(t *testing.T) {
	inv := load(t)
	for key, want := range map[string]AuthMode{
		"GET /v2/orders/{orderId}": AuthRequired, // inherited from the document
		"GET /v2/catalog":          AuthNone,     // security: []
		"GET /v2/maybe":            AuthOptional, // an empty alternative
		"GET /healthz":             AuthNone,     // public, but a health path
	} {
		if got := op(t, inv, key).Auth; got != want {
			t.Errorf("%s: auth %q, want %q", key, got, want)
		}
	}
}

func TestCandidateClasses(t *testing.T) {
	inv := load(t)
	cases := []struct {
		key  string
		want []Class
		not  []Class
	}{
		{"GET /v2/orders/{orderId}", []Class{ClassObjectLevel, ClassDataExposure}, []Class{ClassUnauthenticated, ClassLifecycle}},
		{"PATCH /v2/orders/{orderId}", []Class{ClassObjectLevel, ClassPropertyLevel}, nil},
		{"GET /v2/orders", []Class{ClassResource}, []Class{ClassObjectLevel}},
		{"POST /v2/admin/users", []Class{ClassFunctionLevel, ClassPropertyLevel}, nil},
		{"POST /v2/orders/{orderId}/approve", []Class{ClassFunctionLevel, ClassObjectLevel}, nil},
		{"POST /v2/webhooks", []Class{ClassSSRF}, nil},
		{"POST /v2/files", []Class{ClassUpload}, nil},
		{"GET /v2/catalog", []Class{ClassUnauthenticated}, nil},
		{"GET /healthz", nil, []Class{ClassUnauthenticated}}, // a health path is expected to be public
		{"GET /v1/orders/{orderId}", []Class{ClassObjectLevel, ClassLifecycle}, nil},
	}
	for _, c := range cases {
		o := op(t, inv, c.key)
		for _, w := range c.want {
			if !hasClass(o, w) {
				t.Errorf("%s lacks class %s (has %v)", c.key, w, o.Classes)
			}
		}
		for _, n := range c.not {
			if hasClass(o, n) {
				t.Errorf("%s must not carry class %s", c.key, n)
			}
		}
	}
}

func TestOlderVersionBesideNewerIsLifecycle(t *testing.T) {
	// /v1/orders/{orderId} is also deprecated; the newest version of a route is not marked just for being versioned.
	if hasClass(op(t, load(t), "PATCH /v2/orders/{orderId}"), ClassLifecycle) {
		t.Error("the newest version must not be marked lifecycle")
	}
}

func TestExampleValuesAreNeverKept(t *testing.T) {
	inv := load(t)
	dump := fmt.Sprintf("%+v", inv)
	if strings.Contains(dump, "hunter2-super-secret-example") {
		t.Error("an example value from the specification reached the inventory")
	}
	if !contains(op(t, inv, "POST /v2/admin/users").BodyFields, "role") {
		t.Error("the field name must still be recorded")
	}
}

func TestRemoteReferenceIsNotFollowed(t *testing.T) {
	spec := `openapi: 3.0.0
paths:
  /a/{id}:
    get:
      parameters:
        - $ref: "https://evil.example.test/p.yaml#/x"
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "file:///etc/passwd"
`
	inv, err := Import([]byte(spec))
	if err != nil {
		t.Fatal(err)
	}
	w := strings.Join(inv.Warnings, "|")
	if !strings.Contains(w, "https://evil.example.test") || !strings.Contains(w, "file:///etc/passwd") {
		t.Errorf("remote references should be reported, not followed: %v", inv.Warnings)
	}
}

func TestReferenceLoopIsBounded(t *testing.T) {
	spec := `openapi: 3.0.0
paths:
  /a:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema: { $ref: "#/components/schemas/A" }
components:
  schemas:
    A: { $ref: "#/components/schemas/B" }
    B: { $ref: "#/components/schemas/A" }
`
	if _, err := Import([]byte(spec)); err != nil {
		t.Fatalf("a reference loop must be cut, not fail the import: %v", err)
	}
	rec := `openapi: 3.0.0
paths:
  /a:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Node" }
components:
  schemas:
    Node:
      type: object
      properties:
        child: { $ref: "#/components/schemas/Node" }
`
	if _, err := Import([]byte(rec)); err != nil {
		t.Fatalf("a recursive schema must terminate: %v", err)
	}
}

func TestRejectedDocuments(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"no ver":  "paths:\n  /a:\n    get: {}\n",
		"no path": "openapi: 3.0.0\npaths: {}\n",
		"no ops":  "openapi: 3.0.0\npaths:\n  /a: {}\n",
		"garbage": "openapi: [unclosed",
	}
	for name, doc := range cases {
		if _, err := Import([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Import(make([]byte, MaxDocumentBytes+1)); err == nil {
		t.Error("an oversize document was accepted")
	}
}

func TestJSONIsAccepted(t *testing.T) {
	doc := `{"openapi":"3.1.0","info":{"title":"J","version":"1"},"paths":{"/x/{id}":{"get":{"responses":{"200":{"description":"ok"}}}}}}`
	inv, err := Import([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if !hasClass(inv.Operations[0], ClassObjectLevel) {
		t.Error("the JSON operation lost its path parameter")
	}
}

func TestOperationLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString("openapi: 3.0.0\npaths:\n")
	for i := 0; i <= MaxOperations; i++ {
		fmt.Fprintf(&b, "  /p%d:\n    get:\n      responses:\n        \"200\": {description: ok}\n", i)
	}
	if _, err := Import([]byte(b.String())); err == nil {
		t.Error("more than MaxOperations operations were accepted")
	}
}

func TestSuggestedScope(t *testing.T) {
	got := strings.Join(load(t).SuggestedScope(), ",")
	for _, want := range []string{"/v2/orders", "/v2/admin", "/v2/webhooks", "/healthz"} {
		if !strings.Contains(got, want) {
			t.Errorf("scope %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "{") {
		t.Errorf("a template leaked into the scope: %q", got)
	}
}

func TestDrift(t *testing.T) {
	inv := load(t)
	d := inv.Diff([]Observed{
		{"GET", "/v2/orders/ORD-1?x=1"}, // matches a template, query ignored
		{"GET", "/v2/orders"},
		{"get", "/v1/orders/ORD-9"},    // deprecated, in use
		{"GET", "/v1/legacy/dump"},     // not in the specification
		{"DELETE", "/v2/orders/ORD-1"}, // method not in the specification
	})
	if len(d.Undocumented) != 2 {
		t.Errorf("undocumented %v, want the legacy route and the DELETE", d.Undocumented)
	}
	if len(d.DeprecatedInUse) != 1 || d.DeprecatedInUse[0].OperationID != "getOrderV1" {
		t.Errorf("deprecated in use %v", d.DeprecatedInUse)
	}
	if len(d.Unserved) != 11-3 {
		t.Errorf("%d unserved, want 8", len(d.Unserved))
	}
	// A template segment matches exactly one segment, so a deeper route is undocumented.
	deeper := inv.Diff([]Observed{{"GET", "/v2/orders/ORD-1/secret"}})
	if len(deeper.Undocumented) != 1 {
		t.Errorf("a deeper path matched a template: %v", deeper.Undocumented)
	}
}
