package model

import (
	"context"
	"strings"
	"testing"
)

func TestResourceStem(t *testing.T) {
	for in, want := range map[string]string{
		"orders": "order", "categories": "category", "addresses": "address", "Invoices": "invoice",
		"status": "statu", "news": "new", "line-items": "line_item", "user": "user", "": "",
	} {
		if got := ResourceStem(in); got != want {
			t.Errorf("ResourceStem(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNameStem(t *testing.T) {
	for in, want := range map[string]string{
		"orderId": "order", "order_id": "order", "orderRef": "order", "sourceOrderId": "source_order",
		"id": "", "cid": "", "uuid": "", "name": "", "Id": "",
	} {
		if got := NameStem(in); got != want {
			t.Errorf("NameStem(%q) = %q, want %q", in, got, want)
		}
	}
}

const resSpec = `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{
 "/api/orders/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},
 "/api/invoices/{invoiceId}":{"get":{"parameters":[{"name":"invoiceId","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},
 "/api/shops/{sid}/orders/{id}":{"get":{"parameters":[{"name":"sid","in":"path","required":true,"schema":{"type":"string"}},{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},
 "/api/customers/{customer_id}/notes/{note_id}":{"get":{"parameters":[{"name":"customer_id","in":"path","required":true,"schema":{"type":"string"}},{"name":"note_id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},
 "/api/reports/{year}":{"get":{"parameters":[{"name":"year","in":"path","required":true,"schema":{"type":"integer"}}],"responses":{"200":{"description":"ok"}}}},
 "/api/tickets":{"post":{"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"title":{"type":"string"}}}}}},"responses":{"201":{"description":"ok"}}}}
}}`

func TestImportDerivesResourceTypes(t *testing.T) {
	m, err := Import([]byte(resSpec))
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]Operation{}
	for _, o := range m.Operations {
		byPath[o.Method+" "+o.Path] = o
	}
	types := func(p string) string {
		var out []string
		for _, pp := range byPath[p].PathParams {
			out = append(out, pp.Name+"="+pp.ResourceType)
		}
		return strings.Join(out, ",")
	}
	for p, want := range map[string]string{
		"GET /api/orders/{id}":                             "id=order",
		"GET /api/invoices/{invoiceId}":                    "invoiceId=invoice",
		"GET /api/shops/{sid}/orders/{id}":                 "sid=shop,id=order",
		"GET /api/customers/{customer_id}/notes/{note_id}": "customer_id=customer,note_id=note",
		"GET /api/reports/{year}":                          "year=report",
	} {
		if got := types(p); got != want {
			t.Errorf("%s: %s, want %s", p, got, want)
		}
	}
	if got := byPath["GET /api/shops/{sid}/orders/{id}"].PrimaryType(); got != "order" {
		t.Errorf("nested primary = %q", got)
	}
	if got := byPath["POST /api/tickets"].PrimaryType(); got != "" {
		t.Errorf("collection primary = %q", got)
	}
	if got := byPath["POST /api/tickets"].CreatedType(); got != "ticket" {
		t.Errorf("created = %q", got)
	}
	for _, want := range []string{"order", "invoice", "shop", "customer", "note", "ticket"} {
		if !m.HasResourceType(want) {
			t.Errorf("model lacks type %s: %v", want, m.ResourceTypes())
		}
	}
	// deterministic
	m2, _ := Import([]byte(resSpec))
	if strings.Join(m.ResourceTypes(), ",") != strings.Join(m2.ResourceTypes(), ",") {
		t.Fatal("not deterministic")
	}
}

func TestBuildFixtureExistingObjects(t *testing.T) {
	toy, d := newToy(t)
	m := notesModel(freeTextBody(), ClassSetupSafe)
	accts := []Account{
		{Name: "alice", CustomerID: "cust-a", TokenRef: "ref/a", Existing: map[string]string{"note": "pre-1"}},
		{Name: "bob", CustomerID: "cust-b", TokenRef: "ref/b"},
	}
	f, created, err := BuildFixture(context.Background(), m, accts,
		[]SetupOp{{OperationID: "createNote", Body: map[string]any{"count": 1}}}, d, testSecrets, "r1")
	if err != nil {
		t.Fatal(err)
	}
	var pre *int
	for i, o := range f.Objects {
		if o.ID == "pre-1" {
			i := i
			pre = &i
			if o.OwnerID != "cust-a" || o.Kind != "note" {
				t.Fatalf("existing object: %+v", o)
			}
		}
	}
	if pre == nil {
		t.Fatal("existing object not in fixture")
	}
	for _, c := range created {
		if c.ID == "pre-1" {
			t.Fatal("an existing object must never be listed as created (cleanup would delete it)")
		}
	}
	if len(created) != 2 || toy.hits != 2 {
		t.Fatalf("created %d, requests %d", len(created), toy.hits)
	}
	for _, o := range f.Objects {
		if o.ID != "pre-1" && o.Kind != "note" {
			t.Fatalf("created object kind %q", o.Kind)
		}
	}
}

func TestExistingValidation(t *testing.T) {
	m := notesModel(freeTextBody(), ClassSetupSafe)
	cases := map[string]map[string]string{
		"unknown type":  {"widget": "w-1"},
		"slash in id":   {"note": "a/b"},
		"dot id":        {"note": ".."},
		"empty id":      {"note": ""},
		"literal route": {"note": "notes"},
		"space in id":   {"note": "a b"},
		"question mark": {"note": "a?b=1"},
	}
	for name, ex := range cases {
		toy, d := newToy(t)
		accts := []Account{{Name: "alice", CustomerID: "cust-a", TokenRef: "ref/a", Existing: ex}}
		_, _, err := BuildFixture(context.Background(), m, accts,
			[]SetupOp{{OperationID: "createNote", Body: map[string]any{"count": 1}}}, d, testSecrets, "r1")
		if err == nil {
			t.Errorf("%s: want error", name)
		}
		if toy.hits != 0 {
			t.Errorf("%s: %d requests sent before validation", name, toy.hits)
		}
	}
}

// chainModel has an object (a comment) that needs the id of a note.
func chainModel() Model {
	return Model{Operations: []Operation{
		{ID: "createNote", Method: "POST", Path: "/notes", Body: freeTextBody(), Class: ClassSetupSafe},
		{ID: "createComment", Method: "POST", Path: "/comments", Body: &Schema{Type: "object", Properties: map[string]*Schema{
			"note_id": {Type: "string"}, "text": {Type: "string"}}}, Class: ClassSetupSafe},
	}}
}

func TestChainedSetupResolvesPlaceholders(t *testing.T) {
	toy, d := newToy(t)
	accts := []Account{
		{Name: "alice", CustomerID: "cust-a", TokenRef: "ref/a"},
		{Name: "bob", CustomerID: "cust-b", TokenRef: "ref/b", Existing: nil},
	}
	f, created, err := BuildFixture(context.Background(), chainModel(), accts, []SetupOp{
		{OperationID: "createNote", Body: map[string]any{"count": 1}},
		{OperationID: "createComment", Body: map[string]any{"note_id": "{{self.note.id}}", "meta": []any{"x-{{ self.note.id }}"}}},
	}, d, testSecrets, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 4 || len(f.Objects) != 4 {
		t.Fatalf("created %d objects %d", len(created), len(f.Objects))
	}
	// requests: alice note, alice comment, bob note, bob comment. The toy
	// numbers every created object, so each comment names the note right before it.
	want := []string{"note-1", "note-3"}
	var comments []map[string]any
	for _, b := range toy.bodies {
		if _, ok := b["note_id"]; ok {
			comments = append(comments, b)
		}
	}
	if len(comments) != 2 {
		t.Fatalf("comments sent: %d", len(comments))
	}
	for i, c := range comments {
		if c["note_id"] != want[i] {
			t.Fatalf("comment %d note_id = %v want %s", i, c["note_id"], want[i])
		}
		if meta := c["meta"].([]any); meta[0] != "x-"+want[i] {
			t.Fatalf("embedded placeholder: %v", meta)
		}
	}
	for _, raw := range toy.raw {
		if strings.Contains(raw, "{{") {
			t.Fatalf("a placeholder reached the wire: %s", raw)
		}
	}
	for _, o := range f.Objects {
		if o.Kind == "" {
			t.Fatalf("object without kind: %+v", o)
		}
	}
}

func TestChainedSetupUsesExistingObjects(t *testing.T) {
	toy, d := newToy(t)
	accts := []Account{{Name: "alice", CustomerID: "cust-a", TokenRef: "ref/a", Existing: map[string]string{"note": "pre-9"}}}
	_, _, err := BuildFixture(context.Background(), chainModel(), accts, []SetupOp{
		{OperationID: "createComment", Body: map[string]any{"note_id": "{{self.note.id}}"}},
	}, d, testSecrets, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if toy.bodies[0]["note_id"] != "pre-9" {
		t.Fatalf("body: %v", toy.bodies[0])
	}
}

func TestChainedSetupUnresolvablePlaceholderSendsNothing(t *testing.T) {
	for name, body := range map[string]map[string]any{
		"unknown type":       {"note_id": "{{self.ghost.id}}"},
		"later object":       {"note_id": "{{self.comment.id}}"},
		"malformed":          {"note_id": "{{self.note}}"},
		"nested":             {"a": map[string]any{"b": "{{self.ghost.id}}"}},
		"wrong syntax space": {"note_id": "{{ self .note.id }}"},
	} {
		toy, d := newToy(t)
		accts := []Account{{Name: "alice", CustomerID: "cust-a", TokenRef: "ref/a"}}
		_, _, err := BuildFixture(context.Background(), chainModel(), accts, []SetupOp{
			{OperationID: "createNote", Body: map[string]any{"count": 1}},
			{OperationID: "createComment", Body: body},
		}, d, testSecrets, "r1")
		if err == nil {
			t.Errorf("%s: want error", name)
		}
		if toy.hits != 0 {
			t.Errorf("%s: %d requests sent; the chain must be validated before any request", name, toy.hits)
		}
	}
}

func TestChainedSetupMissingForOneAccountFailsBeforeAnyRequest(t *testing.T) {
	toy, d := newToy(t)
	// only alice declares the note; bob would need it from an earlier setup op, which does not exist
	accts := []Account{
		{Name: "alice", CustomerID: "cust-a", TokenRef: "ref/a", Existing: map[string]string{"note": "n1"}},
		{Name: "bob", CustomerID: "cust-b", TokenRef: "ref/b"},
	}
	_, _, err := BuildFixture(context.Background(), chainModel(), accts, []SetupOp{
		{OperationID: "createComment", Body: map[string]any{"note_id": "{{self.note.id}}"}},
	}, d, testSecrets, "r1")
	if err == nil || toy.hits != 0 {
		t.Fatalf("err=%v hits=%d", err, toy.hits)
	}
}
