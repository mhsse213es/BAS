package openapi

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

func loadGraphQL(t *testing.T) *Inventory {
	t.Helper()
	data, err := os.ReadFile("testdata/shop.graphql")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := Import(data)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	return inv
}

func TestGraphQLSDLImportsRootFieldsAsOperations(t *testing.T) {
	inv := loadGraphQL(t)
	if inv.OpenAPIVersion != "graphql" {
		t.Errorf("format: %q", inv.OpenAPIVersion)
	}
	keys := []string{}
	for _, o := range inv.Operations {
		keys = append(keys, o.Key())
		if o.Path != DefaultGraphQLPath {
			t.Errorf("%s: path %s", o.Key(), o.Path)
		}
	}
	want := []string{
		"QUERY /graphql#adminAuditLog", "QUERY /graphql#catalog", "QUERY /graphql#legacyOrder", "QUERY /graphql#me", "QUERY /graphql#order",
		"QUERY /graphql#orders", "QUERY /graphql#search",
		"MUTATION /graphql#approveOrder", "MUTATION /graphql#deleteAccount", "MUTATION /graphql#registerWebhook", "MUTATION /graphql#updateOrder",
	}
	if !slices.Equal(keys, want) {
		t.Errorf("operations:\n got %v\nwant %v", keys, want)
	}
	// Keys are unique, which the inventory needs even though every field shares one path.
	seen := map[string]bool{}
	for _, k := range keys {
		if seen[k] {
			t.Errorf("duplicate key %s", k)
		}
		seen[k] = true
	}
}

func TestGraphQLArgumentsResponsesAndAuth(t *testing.T) {
	inv := loadGraphQL(t)
	upd := op(t, inv, "MUTATION /graphql#updateOrder")
	for _, f := range []string{"id", "patch", "amount", "note", "status"} {
		if !slices.Contains(upd.BodyFields, f) {
			t.Errorf("updateOrder body field %q missing: %v", f, upd.BodyFields)
		}
	}
	o := op(t, inv, "QUERY /graphql#order")
	for _, f := range []string{"id", "total", "customer", "email", "national_id", "orders"} {
		if !slices.Contains(o.ResponseFields, f) {
			t.Errorf("order response field %q missing: %v", f, o.ResponseFields)
		}
	}
	if o.Summary != "Fetch one order by id." {
		t.Errorf("summary: %q", o.Summary)
	}
	// A union return type exposes its members' fields.
	if s := op(t, inv, "QUERY /graphql#search"); !slices.Contains(s.ResponseFields, "national_id") {
		t.Errorf("a union's member fields were not read: %v", s.ResponseFields)
	}
	if got := op(t, inv, "QUERY /graphql#me").Auth; got != AuthRequired {
		t.Errorf("an @auth field: %s", got)
	}
	if got := op(t, inv, "QUERY /graphql#order").Auth; got != AuthUnspecified {
		t.Errorf("a schema declares no authentication: %s", got)
	}
	if !op(t, inv, "QUERY /graphql#legacyOrder").Deprecated {
		t.Error("@deprecated was not read")
	}
	// extend type Query adds to the root type.
	op(t, inv, "QUERY /graphql#catalog")
}

func TestGraphQLClasses(t *testing.T) {
	inv := loadGraphQL(t)
	want := map[string]Class{
		"QUERY /graphql#order":              ClassObjectLevel,
		"QUERY /graphql#legacyOrder":        ClassLifecycle,
		"QUERY /graphql#orders":             ClassResource,
		"QUERY /graphql#adminAuditLog":      ClassFunctionLevel,
		"MUTATION /graphql#updateOrder":     ClassPropertyLevel,
		"MUTATION /graphql#approveOrder":    ClassFunctionLevel,
		"MUTATION /graphql#registerWebhook": ClassSSRF,
		"QUERY /graphql#search":             ClassDataExposure,
	}
	for key, c := range want {
		if !hasClass(op(t, inv, key), c) {
			t.Errorf("%s: classes %v, want %s", key, op(t, inv, key).Classes, c)
		}
	}
	if hasClass(op(t, inv, "QUERY /graphql#catalog"), ClassUnauthenticated) {
		t.Error("an unspecified field must not be called public")
	}
	if got := op(t, inv, "MUTATION /graphql#deleteAccount").Classes; len(got) != 0 {
		t.Errorf("deleteAccount: %v", got)
	}
}

func TestGraphQLDefaultValuesAreNeverKept(t *testing.T) {
	data, _ := os.ReadFile("testdata/shop.graphql")
	inv, err := Import(data)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(inv)
	if strings.Contains(string(b), "hunter2") {
		t.Error("a default value from the schema was kept in the inventory")
	}
}

func TestGraphQLWarningsSayWhatIsAssumed(t *testing.T) {
	w := strings.Join(loadGraphQL(t).Warnings, " | ")
	for _, s := range []string{"does not say where it is served", "authentication", "only GraphQL queries can be bound"} {
		if !strings.Contains(w, s) {
			t.Errorf("warnings do not mention %q: %s", s, w)
		}
	}
}

func TestGraphQLIntrospectionGivesTheSameOperations(t *testing.T) {
	ref := func(kind, name string) map[string]any { return map[string]any{"kind": kind, "name": name} }
	nonNull := func(of map[string]any) map[string]any { return map[string]any{"kind": "NON_NULL", "ofType": of} }
	list := func(of map[string]any) map[string]any { return map[string]any{"kind": "LIST", "ofType": of} }
	doc := map[string]any{"data": map[string]any{"__schema": map[string]any{
		"queryType":    map[string]any{"name": "Query"},
		"mutationType": map[string]any{"name": "Mutation"},
		"types": []any{
			map[string]any{"kind": "OBJECT", "name": "Query", "fields": []any{
				map[string]any{"name": "order", "description": "Fetch one order by id.", "args": []any{
					map[string]any{"name": "id", "type": nonNull(ref("SCALAR", "ID"))}}, "type": ref("OBJECT", "Order")},
				map[string]any{"name": "orders", "args": []any{
					map[string]any{"name": "limit", "type": ref("SCALAR", "Int")}}, "type": list(nonNull(ref("OBJECT", "Order")))},
				map[string]any{"name": "old", "isDeprecated": true, "args": []any{}, "type": ref("OBJECT", "Order")},
				map[string]any{"name": "__typename", "args": []any{}, "type": ref("SCALAR", "String")},
			}},
			map[string]any{"kind": "OBJECT", "name": "Mutation", "fields": []any{
				map[string]any{"name": "updateOrder", "args": []any{
					map[string]any{"name": "id", "type": ref("SCALAR", "ID")},
					map[string]any{"name": "patch", "type": nonNull(ref("INPUT_OBJECT", "OrderPatch"))}}, "type": ref("OBJECT", "Order")}}},
			map[string]any{"kind": "OBJECT", "name": "Order", "fields": []any{
				map[string]any{"name": "id", "args": []any{}, "type": ref("SCALAR", "ID")},
				map[string]any{"name": "email", "args": []any{}, "type": ref("SCALAR", "String")},
			}},
			map[string]any{"kind": "INPUT_OBJECT", "name": "OrderPatch", "inputFields": []any{
				map[string]any{"name": "status", "type": ref("SCALAR", "String")}}},
			map[string]any{"kind": "OBJECT", "name": "__Schema"},
		},
	}}}
	data, _ := json.Marshal(doc)
	inv, err := Import(data)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	var keys []string
	for _, o := range inv.Operations {
		keys = append(keys, o.Key())
	}
	want := []string{"QUERY /graphql#old", "QUERY /graphql#order", "QUERY /graphql#orders", "MUTATION /graphql#updateOrder"}
	if !slices.Equal(keys, want) {
		t.Errorf("operations: got %v want %v", keys, want)
	}
	if !op(t, inv, "QUERY /graphql#old").Deprecated {
		t.Error("isDeprecated was not read")
	}
	if o := op(t, inv, "QUERY /graphql#order"); o.Summary != "Fetch one order by id." || !hasClass(o, ClassObjectLevel) || !hasClass(o, ClassDataExposure) {
		t.Errorf("order: %+v", o)
	}
	if u := op(t, inv, "MUTATION /graphql#updateOrder"); !hasClass(u, ClassPropertyLevel) || !slices.Contains(u.BodyFields, "status") {
		t.Errorf("updateOrder: %+v", u)
	}
	// The bare form (no data wrapper) is the same schema.
	inner, _ := json.Marshal(doc["data"])
	if _, err := Import(inner); err != nil {
		t.Errorf("bare __schema form: %v", err)
	}
}

func TestGraphQLRefusals(t *testing.T) {
	cases := map[string]string{
		"no root fields":       "type Query\n",
		"empty root":           "type Query {\n}\n",
		"unclosed type":        "type Query {\n  a: String\n",
		"unclosed args":        "type Query {\n  a(x: Int : String\n}\n",
		"unclosed string":      "type Query {\n  \"oops\n  a: String\n}\n",
		"unclosed block":       "type Query {\n  \"\"\"oops\n  a: String\n}\n",
		"stray keyword":        "type Query { a: String }\nfragment F on Query { a }\n",
		"bad character":        "type Query { a: String }\n%\n",
		"introspection empty":  `{"__schema": {}}`,
		"introspection broken": `{"__schema": `,
	}
	for name, doc := range cases {
		if _, err := Import([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGraphQLErrorsNameTheLine(t *testing.T) {
	_, err := Import([]byte("type Query {\n  a: String\n}\ntype Mutation {\n  b(x Int): String\n}\n"))
	if err == nil || !strings.Contains(err.Error(), "line 5") {
		t.Errorf("error should name line 5: %v", err)
	}
}

func TestGraphQLIsNotMistakenForOpenAPI(t *testing.T) {
	// An OpenAPI document that mentions a Query type in a schema stays OpenAPI.
	doc := "openapi: 3.0.0\npaths:\n  /a:\n    get:\n      responses: {\"200\": {description: ok}}\ncomponents:\n  schemas:\n    Query:\n      type: object\n"
	inv, err := Import([]byte(doc))
	if err != nil || inv.OpenAPIVersion != "3.0.0" {
		t.Errorf("openapi document: %v %v", inv, err)
	}
	if looksLikeGraphQL([]byte(`{"openapi":"3.0.0","paths":{}}`)) {
		t.Error("an OpenAPI JSON document was read as GraphQL")
	}
}

func TestGraphQLLegacyShapesAndLimits(t *testing.T) {
	// Without a schema block the roots are the conventional names; commas are whitespace; a comment and a BOM are tolerated.
	inv, err := Import([]byte("\ufeff# c\ntype Query { a(x: Int, y: [String!]! = [\"k\"]): String, b: Int }\n"))
	if err != nil || len(inv.Operations) != 2 {
		t.Fatalf("legacy: %v %v", inv, err)
	}
	// A renamed root type through the schema block.
	inv, err = Import([]byte("schema { query: RootQuery }\ntype RootQuery { a: String }\n"))
	if err != nil || inv.Operations[0].Key() != "QUERY /graphql#a" {
		t.Errorf("renamed root: %v %v", inv, err)
	}
	// A self-referencing type is bounded.
	inv, err = Import([]byte("type Query { n: Node }\ntype Node { next: Node, id: ID, other: Node }\n"))
	if err != nil || !slices.Contains(inv.Operations[0].ResponseFields, "next") {
		t.Errorf("recursive type: %v %v", inv, err)
	}
	// A root field declared twice is one operation.
	inv, err = Import([]byte("type Query { a: Int }\nextend type Query { a: Int, b: Int }\n"))
	if err != nil || len(inv.Operations) != 2 {
		t.Errorf("duplicate field: %v %v", inv, err)
	}
	// Too many root fields.
	var b strings.Builder
	b.WriteString("type Query {\n")
	for i := 0; i <= MaxOperations; i++ {
		fmt.Fprintf(&b, "  f%d", i)
		b.WriteString(": Int\n")
	}
	b.WriteString("}\n")
	if _, err := Import([]byte(b.String())); err == nil {
		t.Error("an oversize schema was accepted")
	}
}

func TestGraphQLCamelCasePrivilegedNames(t *testing.T) {
	for name, want := range map[string]bool{
		"adminDeleteUser": true, "approve_loan": true, "refundOrder": true, "impersonateUser": true,
		"order": false, "orders": false, "administrator": false, "systematic": false, "release": true,
	} {
		if privateName(name) != want {
			t.Errorf("privateName(%q) = %v, want %v", name, !want, want)
		}
	}
}
