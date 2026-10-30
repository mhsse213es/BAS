package model

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func load(t *testing.T, name string) Model {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Import(b)
	if err != nil {
		t.Fatalf("Import(%s): %v", name, err)
	}
	return m
}

func find(t *testing.T, m Model, id string) Operation {
	t.Helper()
	for _, o := range m.Operations {
		if o.ID == id {
			return o
		}
	}
	t.Fatalf("operation %q not found in %v", id, ids(m))
	return Operation{}
}

func ids(m Model) []string {
	var out []string
	for _, o := range m.Operations {
		out = append(out, o.ID)
	}
	return out
}

func TestImportResolvesRefs(t *testing.T) {
	m := load(t, "items.json")
	list := find(t, m, "listItems")
	if len(list.QueryParams) != 2 || list.QueryParams[0].Name != "limit" || list.QueryParams[0].Schema == nil || list.QueryParams[0].Schema.Type != "integer" {
		t.Fatalf("component parameter not resolved: %+v", list.QueryParams)
	}
	create := find(t, m, "createItem")
	if create.Body == nil {
		t.Fatal("body not resolved through requestBody and schema refs")
	}
	if create.Body.Properties["name"] == nil || create.Body.Properties["qty"] == nil || create.Body.Properties["tags"] == nil {
		t.Fatalf("allOf not flattened: %v", create.Body.PropertyNames())
	}
	if create.Body.Properties["tags"].Items == nil || create.Body.Properties["tags"].Items.Type != "string" {
		t.Fatal("array items lost")
	}
	if len(create.Body.Required) != 1 || create.Body.Required[0] != "name" {
		t.Fatalf("required = %v", create.Body.Required)
	}
	if len(m.NotModelled) != 0 {
		t.Fatalf("unexpected NotModelled: %v", m.NotModelled)
	}
	for _, o := range m.Operations {
		if o.Class != ClassUnknown {
			t.Fatalf("%s class = %q, want unknown", o.ID, o.Class)
		}
	}
}

func TestImportReportsUnresolvableAsNotModelled(t *testing.T) {
	m := load(t, "unresolvable.json")
	joined := strings.Join(m.NotModelled, "\n")
	for _, want := range []string{"#/components/schemas/Missing", "https://example.com/x.json", "callbacks", "oneOf", "#/components/parameters/Nope", "recursive"} {
		if !strings.Contains(joined, want) {
			t.Errorf("NotModelled lacks %q:\n%s", want, joined)
		}
	}
	for _, id := range []string{"postA", "postB", "postC", "getD", "postE"} {
		find(t, m, id)
	}
	if find(t, m, "postA").Body != nil {
		t.Error("unresolvable body must not be guessed")
	}
	if find(t, m, "postC").Body != nil {
		t.Error("unflattenable oneOf body must not be guessed")
	}
}

func TestImportNeverPanicsOnMalformed(t *testing.T) {
	cases := map[string]string{
		"empty":        ``,
		"whitespace":   "  \n",
		"truncated":    `{"openapi":"3.0.3","paths":{"/a":{"get":`,
		"not json":     `openapi: 3.0.0`,
		"array":        `[]`,
		"null":         `null`,
		"number":       `42`,
		"not openapi":  `{"hello":"world"}`,
		"paths string": `{"openapi":"3.0.0","paths":"x"}`,
		"path null":    `{"openapi":"3.0.0","paths":{"/a":null}}`,
		"op string":    `{"openapi":"3.0.0","paths":{"/a":{"get":"x"}}}`,
		"params wrong": `{"openapi":"3.0.0","paths":{"/a":{"get":{"parameters":"x"}}}}`,
		"ref only":     `{"openapi":"3.0.0","paths":{"/a":{"get":{"parameters":[{"$ref":"#"}]}}}}`,
		"bad pointer":  `{"openapi":"3.0.0","paths":{"/a":{"get":{"requestBody":{"$ref":"#/components/"}}}}}`,
		"schema list":  `{"openapi":"3.0.0","paths":{"/a":{"post":{"requestBody":{"content":{"application/json":{"schema":[]}}}}}}}`,
		"type array":   `{"openapi":"3.0.0","paths":{"/a":{"post":{"requestBody":{"content":{"application/json":{"schema":{"type":["string","null"]}}}}}}}}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			_, _ = Import([]byte(in))
		})
	}
	for _, in := range []string{``, `{"hello":"world"}`, `[]`, `{"openapi":"3.0.3","paths":{"/a":{"get":`} {
		if _, err := Import([]byte(in)); err == nil {
			t.Errorf("Import(%q) should return an error", in)
		}
	}
}

func TestImportMarksObjectIDParams(t *testing.T) {
	m := load(t, "items.json")
	byName := func(ps []Param, n string) Param {
		for _, p := range ps {
			if p.Name == n {
				return p
			}
		}
		t.Fatalf("param %q missing in %+v", n, ps)
		return Param{}
	}
	if p := byName(find(t, m, "listItems").QueryParams, "owner_id"); !p.IsObjectID {
		t.Error("owner_id should be an object id")
	}
	if p := byName(find(t, m, "listItems").QueryParams, "limit"); p.IsObjectID {
		t.Error("limit should not be an object id")
	}
	if p := byName(find(t, m, "delete_items_by_id").QueryParams, "force"); p.IsObjectID {
		t.Error("force should not be an object id")
	}
	id := byName(find(t, m, "get_items_by_id").PathParams, "id")
	if !id.IsObjectID || id.Resource != "items" {
		t.Errorf("id = %+v", id)
	}
	deep := find(t, m, "get_notes_by_noteref_tags_by_label")
	if p := byName(deep.PathParams, "noteRef"); !p.IsObjectID || p.Resource != "notes" {
		t.Errorf("noteRef = %+v", p)
	}
	// Not matched by name, but sits under a collection segment.
	if p := byName(deep.PathParams, "label"); !p.IsObjectID || p.Resource != "tags" {
		t.Errorf("label = %+v", p)
	}
}

func TestImportHandlesPathLevelParameters(t *testing.T) {
	m := load(t, "items.json")
	for _, id := range []string{"get_items_by_id", "delete_items_by_id"} {
		o := find(t, m, id)
		if len(o.PathParams) != 1 || o.PathParams[0].Name != "id" || !o.PathParams[0].Required {
			t.Errorf("%s PathParams = %+v", id, o.PathParams)
		}
	}
	if q := find(t, m, "delete_items_by_id").QueryParams; len(q) != 1 || q[0].Name != "force" {
		t.Errorf("operation-level query params lost: %+v", q)
	}
}

func TestImportOperationWithoutOperationIDGetsStableID(t *testing.T) {
	m := load(t, "items.json")
	o := find(t, m, "get_items_by_id")
	if o.Method != "GET" || o.Path != "/items/{id}" {
		t.Errorf("got %+v", o)
	}
	again := load(t, "items.json")
	if strings.Join(ids(m), ",") != strings.Join(ids(again), ",") {
		t.Error("ordering/ids not deterministic")
	}
	seen := map[string]bool{}
	for _, id := range ids(m) {
		if seen[id] {
			t.Errorf("duplicate id %s", id)
		}
		seen[id] = true
	}
}

func TestImportSecurityInheritance(t *testing.T) {
	m := load(t, "items.json")
	if s := find(t, m, "listItems").Security; len(s) != 1 || s[0] != "bearer" {
		t.Errorf("inherited security = %v", s)
	}
	if s := find(t, m, "delete_items_by_id").Security; len(s) != 0 {
		t.Errorf("explicit empty security = %v", s)
	}
}

func TestImportDuplicateOperationIDsAreMadeUnique(t *testing.T) {
	doc := `{"openapi":"3.0.0","paths":{"/a":{"get":{"operationId":"x"}},"/b":{"get":{"operationId":"x"}}}}`
	m, err := Import([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ids(m), ","); got != "x,x_2" {
		t.Errorf("ids = %s", got)
	}
	if len(m.NotModelled) == 0 {
		t.Error("duplicate id should be noted")
	}
}

func importWithin(t *testing.T, doc string, d time.Duration) Model {
	t.Helper()
	type res struct {
		m   Model
		err error
	}
	ch := make(chan res, 1)
	go func() {
		m, err := Import([]byte(doc))
		ch <- res{m, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("Import: %v", r.err)
		}
		return r.m
	case <-time.After(d):
		t.Fatal("Import did not finish in time")
	}
	return Model{}
}

func bodyDoc(schemas, body string) string {
	return `{"openapi":"3.0.0","paths":{"/a":{"post":{"operationId":"p","requestBody":{"content":{"application/json":{"schema":` +
		body + `}}}}}},"components":{"schemas":{` + schemas + `}}}`
}

func TestImportRefDAGDoesNotExplode(t *testing.T) {
	var parts []string
	for i := 0; i < 22; i++ {
		next := fmt.Sprintf("S%d", i+1)
		parts = append(parts, fmt.Sprintf(`"S%d":{"type":"object","properties":{"a":{"$ref":"#/components/schemas/%s"},"b":{"$ref":"#/components/schemas/%s"}}}`, i, next, next))
	}
	parts = append(parts, `"S22":{"type":"string"}`)
	m := importWithin(t, bodyDoc(strings.Join(parts, ","), `{"$ref":"#/components/schemas/S0"}`), 5*time.Second)
	if find(t, m, "p").Body == nil {
		t.Fatal("body should be modelled")
	}
}

func TestImportDeeplyNestedInlineSchema(t *testing.T) {
	const depth = 5000
	nested := strings.Repeat(`{"type":"array","items":`, depth) + `{"type":"string"}` + strings.Repeat(`}`, depth)
	m := importWithin(t, bodyDoc("", nested), 10*time.Second)
	_ = find(t, m, "p")
	if !strings.Contains(strings.Join(m.NotModelled, "\n"), "deeper than") {
		t.Errorf("depth truncation not reported: %v", m.NotModelled)
	}
}

func TestImportNodeBudgetTruncates(t *testing.T) {
	var props []string
	for i := 0; i < maxSchemaNodes+10; i++ {
		props = append(props, fmt.Sprintf(`"p%d":{"type":"string"}`, i))
	}
	m := importWithin(t, bodyDoc("", `{"type":"object","properties":{`+strings.Join(props, ",")+`}}`), 10*time.Second)
	if !strings.Contains(strings.Join(m.NotModelled, "\n"), "budget") {
		t.Error("budget exhaustion not reported")
	}
}

func TestImportReportsUndeclaredPathTemplateParam(t *testing.T) {
	m, err := Import([]byte(`{"openapi":"3.0.0","paths":{"/a/{x}/b/{y}":{"get":{"operationId":"g","parameters":[{"name":"y","in":"path","required":true}]}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	j := strings.Join(m.NotModelled, "\n")
	if !strings.Contains(j, `"x"`) || strings.Contains(j, `"y" has no declaration`) {
		t.Errorf("notes = %s", j)
	}
}

func TestImportReportsUnsupportedPathItemKeys(t *testing.T) {
	m, err := Import([]byte(`{"openapi":"3.0.0","paths":{"/a":{"summary":"s","description":"d","servers":[],"parameters":[],"x-foo":1,"GET":{},"connect":{},"query":{},"get":{"operationId":"g"}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	j := strings.Join(m.NotModelled, "\n")
	for _, k := range []string{`"GET"`, `"connect"`, `"query"`} {
		if !strings.Contains(j, k) {
			t.Errorf("missing note for %s: %s", k, j)
		}
	}
	for _, k := range []string{`"summary"`, `"description"`, `"servers"`, `"parameters"`, `"x-foo"`} {
		if strings.Contains(j, k) {
			t.Errorf("legit key %s reported: %s", k, j)
		}
	}
	if len(m.Operations) != 1 {
		t.Errorf("ops = %v", ids(m))
	}
}

func TestImportAllOfConflictsAreReportedNotGuessed(t *testing.T) {
	cases := map[string]string{
		"enum disjoint": `{"allOf":[{"type":"string","enum":["a"]},{"type":"string","enum":["b"]}]}`,
		"format":        `{"allOf":[{"type":"string","format":"date"},{"type":"string","format":"uuid"}]}`,
		"pattern":       `{"allOf":[{"type":"string","pattern":"^a"},{"type":"string","pattern":"^b"}]}`,
		"property":      `{"allOf":[{"type":"object","properties":{"x":{"type":"string"}}},{"type":"object","properties":{"x":{"type":"integer"}}}]}`,
		"type":          `{"allOf":[{"type":"string"},{"type":"integer"}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			m, err := Import([]byte(bodyDoc("", body)))
			if err != nil {
				t.Fatal(err)
			}
			if find(t, m, "p").Body != nil {
				t.Error("conflicting allOf must not be modelled")
			}
			if !strings.Contains(strings.Join(m.NotModelled, "\n"), "allOf conflict") {
				t.Errorf("not reported: %v", m.NotModelled)
			}
		})
	}
}

func TestImportAllOfMergesExactly(t *testing.T) {
	body := `{"allOf":[{"type":"integer","minimum":1,"maximum":100,"enum":[1,2,3]},{"type":"integer","minimum":5,"maximum":50,"enum":[3,4]}]}`
	m, err := Import([]byte(bodyDoc("", body)))
	if err != nil {
		t.Fatal(err)
	}
	b := find(t, m, "p").Body
	if b == nil || *b.Minimum != 5 || *b.Maximum != 50 || len(b.Enum) != 1 {
		t.Fatalf("merge = %+v", b)
	}
}

func TestImportReportsIgnoredSchemaKeywords(t *testing.T) {
	body := `{"type":"object","additionalProperties":false,"discriminator":{"propertyName":"k"},"properties":{"a":{"type":"string","readOnly":true,"writeOnly":false,"default":"x"}}}`
	m, err := Import([]byte(bodyDoc("", body)))
	if err != nil {
		t.Fatal(err)
	}
	j := strings.Join(m.NotModelled, "\n")
	for _, w := range []string{`"additionalProperties"`, `"discriminator"`, `"readOnly"`, `"writeOnly"`, `"default"`, "requestBody.properties.a"} {
		if !strings.Contains(j, w) {
			t.Errorf("missing %s in:\n%s", w, j)
		}
	}
}
