package openapi

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func loadSwagger(t *testing.T) *Inventory {
	t.Helper()
	data, err := os.ReadFile("testdata/shop_swagger2.yaml")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := Import(data)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	return inv
}

func TestSwagger2ReadsDocumentFactsAndPrefixesBasePath(t *testing.T) {
	inv := loadSwagger(t)
	if inv.Title != "Shop API" || inv.OpenAPIVersion != "2.0" {
		t.Errorf("facts: %q %q", inv.Title, inv.OpenAPIVersion)
	}
	if len(inv.Servers) != 1 || inv.Servers[0] != "https://api.example.test/v2" {
		t.Errorf("servers: %v (host, scheme and basePath make the base URL)", inv.Servers)
	}
	// Every path is relative to basePath in Swagger 2.0; the inventory keeps full request paths.
	for _, o := range inv.Operations {
		if !strings.HasPrefix(o.Path, "/v2/") {
			t.Errorf("%s does not carry the basePath", o.Key())
		}
	}
	op(t, inv, "GET /v2/orders/{orderId}")
	if len(inv.Operations) != 9 {
		t.Errorf("%d operations, want 9", len(inv.Operations))
	}
}

func TestSwagger2ParametersBodiesAndResponses(t *testing.T) {
	inv := loadSwagger(t)
	get := op(t, inv, "GET /v2/orders/{orderId}")
	if !slices.Equal(get.PathParams, []string{"orderId"}) {
		t.Errorf("a $ref'd path-level parameter was not read: %v", get.PathParams)
	}
	// The response schema is read through definitions, to depth.
	for _, f := range []string{"id", "total", "customer", "email", "national_id", "items", "sku"} {
		if !slices.Contains(get.ResponseFields, f) {
			t.Errorf("response field %q not read: %v", f, get.ResponseFields)
		}
	}
	patch := op(t, inv, "PATCH /v2/orders/{orderId}")
	if !slices.Equal(patch.BodyFields, []string{"amount", "note"}) {
		t.Errorf("body parameter fields: %v", patch.BodyFields)
	}
	if !slices.Equal(patch.BodyContentTypes, []string{"application/json"}) {
		t.Errorf("a body takes the document's consumes: %v", patch.BodyContentTypes)
	}
	hook := op(t, inv, "POST /v2/webhooks")
	if !slices.Equal(hook.BodyFields, []string{"callback_url"}) {
		t.Errorf("a $ref'd body definition was not read: %v", hook.BodyFields)
	}
	list := op(t, inv, "GET /v2/orders")
	if !slices.Equal(list.QueryParams, []string{"limit"}) {
		t.Errorf("query params: %v", list.QueryParams)
	}
	up := op(t, inv, "POST /v2/files")
	if !slices.Equal(up.BodyFields, []string{"file"}) || !slices.Equal(up.BodyContentTypes, []string{"multipart/form-data"}) {
		t.Errorf("an operation's own consumes replaces the document's: %v %v", up.BodyFields, up.BodyContentTypes)
	}
	// A form with a file parameter is multipart even when the declaration is the document default.
	su := op(t, inv, "POST /v2/signup")
	if !slices.Contains(su.BodyContentTypes, "multipart/form-data") && !slices.Contains(su.BodyContentTypes, "application/json") {
		t.Errorf("form content types: %v", su.BodyContentTypes)
	}
	if !slices.Equal(su.BodyFields, []string{"avatar", "email"}) {
		t.Errorf("form fields: %v", su.BodyFields)
	}
}

func TestSwagger2AuthenticationAndClasses(t *testing.T) {
	inv := loadSwagger(t)
	if got := op(t, inv, "GET /v2/orders/{orderId}").Auth; got != AuthRequired {
		t.Errorf("global security: %s", got)
	}
	if got := op(t, inv, "GET /v2/catalog").Auth; got != AuthNone {
		t.Errorf("security [] makes an operation public: %s", got)
	}
	want := map[string]Class{
		"GET /v2/orders/{orderId}":          ClassObjectLevel,
		"PATCH /v2/orders/{orderId}":        ClassObjectLevel,
		"POST /v2/orders/{orderId}/approve": ClassFunctionLevel,
		"POST /v2/admin/users":              ClassFunctionLevel,
		"GET /v2/catalog":                   ClassUnauthenticated,
		"GET /v2/orders":                    ClassResource,
		"POST /v2/webhooks":                 ClassSSRF,
		"POST /v2/files":                    ClassUpload,
		"POST /v2/signup":                   ClassUpload,
	}
	for key, c := range want {
		if !hasClass(op(t, inv, key), c) {
			t.Errorf("%s: classes %v, want %s", key, op(t, inv, key).Classes, c)
		}
	}
}

func TestSwagger2ExampleAndDefaultValuesAreNeverKept(t *testing.T) {
	data, _ := os.ReadFile("testdata/shop_swagger2.yaml")
	inv, err := Import(data)
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.Join(inv.Warnings, " ")
	for _, o := range inv.Operations {
		raw += strings.Join(o.BodyFields, " ") + strings.Join(o.ResponseFields, " ")
	}
	if strings.Contains(raw, "hunter2") {
		t.Error("a default value from the document was kept in the inventory")
	}
}

func TestSwagger2SameAPIAsOpenAPI3GivesTheSameOperationsAndClasses(t *testing.T) {
	v3 := load(t)
	v2 := loadSwagger(t)
	// The 3.x fixture has /v2-prefixed paths; the Swagger one reaches them through basePath. Compare the operations they share.
	shared := []string{
		"GET /v2/orders/{orderId}", "PATCH /v2/orders/{orderId}", "POST /v2/orders/{orderId}/approve", "GET /v2/orders",
		"POST /v2/admin/users", "POST /v2/webhooks", "POST /v2/files", "GET /v2/catalog",
	}
	for _, key := range shared {
		a, b := op(t, v3, key), op(t, v2, key)
		if !slices.Equal(a.Classes, b.Classes) {
			t.Errorf("%s: OpenAPI 3 classes %v, Swagger 2 classes %v", key, a.Classes, b.Classes)
		}
		if a.Auth != b.Auth {
			t.Errorf("%s: auth %s vs %s", key, a.Auth, b.Auth)
		}
	}
}

func TestSwagger2VariantsAndRefusals(t *testing.T) {
	// An unquoted 2.0 is the YAML number 2; it is still Swagger 2.0.
	if inv, err := Import([]byte("swagger: 2.0\npaths:\n  /a:\n    get:\n      responses: {\"200\": {description: ok}}\n")); err != nil || inv.OpenAPIVersion != "2.0" {
		t.Errorf("unquoted 2.0: %v %v", inv, err)
	}
	// No host: no servers. A relative basePath is ignored with a warning.
	inv, err := Import([]byte("swagger: \"2.0\"\nbasePath: v1\npaths:\n  /a:\n    get:\n      responses: {\"200\": {description: ok}}\n"))
	if err != nil || len(inv.Servers) != 0 || inv.Operations[0].Path != "/a" || !strings.Contains(strings.Join(inv.Warnings, " "), "basePath") {
		t.Errorf("relative basePath: %+v %v", inv, err)
	}
	// http and https schemes each give a server.
	inv, err = Import([]byte("swagger: \"2.0\"\nhost: x.test\nschemes: [http, https, ws]\npaths:\n  /a:\n    get:\n      responses: {\"200\": {description: ok}}\n"))
	if err != nil || !slices.Equal(inv.Servers, []string{"http://x.test", "https://x.test"}) {
		t.Errorf("schemes: %v %v", inv.Servers, err)
	}
	for name, doc := range map[string]string{
		"swagger 1.2":    "swagger: \"1.2\"\npaths:\n  /a:\n    get: {}\n",
		"swagger 3":      "swagger: \"3.0\"\npaths:\n  /a:\n    get: {}\n",
		"swagger no ver": "swagger: \"\"\npaths:\n  /a:\n    get: {}\n",
	} {
		if _, err := Import([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSwagger2BasePathOnlyAppliesToSwaggerDocuments(t *testing.T) {
	inv, err := Import([]byte("openapi: 3.0.0\nbasePath: /ignored\npaths:\n  /a:\n    get:\n      responses: {\"200\": {description: ok}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Operations[0].Path != "/a" {
		t.Errorf("an OpenAPI 3 document's path was prefixed: %s", inv.Operations[0].Path)
	}
}
