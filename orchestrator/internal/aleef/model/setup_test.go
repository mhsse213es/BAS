package model

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// toyNotes is a generic notes API: POST /notes creates a note and returns its id.
type toyNotes struct {
	mu     sync.Mutex
	n      int
	bodies []map[string]any
	auths  []string
	hits   int
	raw    []string
	urls   []string
	failAt int // 1-based request number that returns 500
	noID   int // 1-based request number that returns 201 without an id
}

func (t *toyNotes) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.hits++
	var b map[string]any
	rb, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(rb, &b)
	t.raw = append(t.raw, string(rb))
	t.urls = append(t.urls, r.URL.String())
	if t.hits == t.failAt {
		w.WriteHeader(500)
		return
	}
	if t.hits == t.noID {
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"title":"x"}`))
		return
	}
	t.bodies = append(t.bodies, b)
	t.auths = append(t.auths, r.Header.Get("Authorization"))
	t.n++
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	_ = json.NewEncoder(w).Encode(map[string]any{"id": fmt.Sprintf("note-%d", t.n)})
}

type rewriteDoer struct{ base *url.URL }

func (d rewriteDoer) Do(r *http.Request) (*http.Response, error) {
	r.URL.Scheme = d.base.Scheme
	r.URL.Host = d.base.Host
	return http.DefaultClient.Do(r)
}

type mapSecrets map[string]string

func (m mapSecrets) Resolve(ref string) (string, error) {
	v, ok := m[ref]
	if !ok {
		return "", fmt.Errorf("no secret")
	}
	return v, nil
}

func notesModel(body *Schema, class OpClass) Model {
	return Model{Operations: []Operation{
		{ID: "createNote", Method: "POST", Path: "/notes", Body: body, Class: class},
		{ID: "deleteNote", Method: "DELETE", Path: "/notes/{id}", Class: ClassReversible},
	}}
}

func freeTextBody() *Schema {
	return &Schema{Type: "object", Properties: map[string]*Schema{
		"count":    {Type: "integer"},
		"kind":     {Type: "string", Enum: []any{"a", "b"}},
		"owner_id": {Type: "string"},
		"title":    {Type: "string"},
	}}
}

var testAccounts = []Account{
	{Name: "alice", CustomerID: "cust-a", TokenRef: "ref/a", Role: "user"},
	{Name: "bob", CustomerID: "cust-b", TokenRef: "ref/b", Role: "user"},
}

var testSecrets = mapSecrets{"ref/a": "tok-secret-a", "ref/b": "tok-secret-b"}

func newToy(t *testing.T) (*toyNotes, rewriteDoer) {
	toy := &toyNotes{}
	srv := httptest.NewServer(toy)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return toy, rewriteDoer{base: u}
}

func TestBuildFixtureCreatesObjectPerAccount(t *testing.T) {
	toy, d := newToy(t)
	m := notesModel(freeTextBody(), ClassSetupSafe)
	f, created, err := BuildFixture(context.Background(), m, testAccounts,
		[]SetupOp{{OperationID: "createNote", Body: map[string]any{"count": 1}}}, d, testSecrets, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Identities) != 2 || len(f.Objects) != 2 || len(created) != 2 {
		t.Fatalf("got %d identities %d objects %d created", len(f.Identities), len(f.Objects), len(created))
	}
	if f.Objects[0].ID != "note-1" || f.Objects[0].OwnerID != "cust-a" || f.Objects[1].OwnerID != "cust-b" {
		t.Fatalf("objects: %+v", f.Objects)
	}
	if f.Identities[0].TokenRef != "ref/a" || f.Identities[1].Name != "bob" {
		t.Fatalf("identities: %+v", f.Identities)
	}
	if toy.auths[0] != "Bearer tok-secret-a" || toy.auths[1] != "Bearer tok-secret-b" {
		t.Fatalf("auth: %v", toy.auths)
	}
}

func TestBuildFixtureEmbedsCanaryInFreeTextField(t *testing.T) {
	toy, d := newToy(t)
	m := notesModel(freeTextBody(), ClassSetupSafe)
	f, _, err := BuildFixture(context.Background(), m, testAccounts,
		[]SetupOp{{OperationID: "createNote", Body: map[string]any{"count": 1, "title": "operator"}}}, d, testSecrets, "r1")
	if err != nil {
		t.Fatal(err)
	}
	want := "ALEEF-CANARY-r1-alice"
	if toy.bodies[0]["title"] != want {
		t.Fatalf("title = %v", toy.bodies[0]["title"])
	}
	if toy.bodies[0]["count"] != float64(1) {
		t.Fatalf("operator field lost: %v", toy.bodies[0])
	}
	if !strings.Contains(toy.raw[1], `"title":"ALEEF-CANARY-r1-bob"`) {
		t.Fatalf("wire body: %s", toy.raw[1])
	}
	for i := range toy.raw {
		if strings.Contains(toy.raw[i], "tok-secret") || strings.Contains(toy.urls[i], "tok-secret") {
			t.Fatalf("token outside Authorization header in request %d", i)
		}
	}
	if f.Objects[0].Protected["canary"] != want || f.Objects[1].Protected["canary"] != "ALEEF-CANARY-r1-bob" {
		t.Fatalf("protected: %+v", f.Objects)
	}
}

func TestBuildFixtureWithoutFreeTextMarksStructuralOnly(t *testing.T) {
	_, d := newToy(t)
	body := &Schema{Type: "object", Properties: map[string]*Schema{
		"count": {Type: "integer"},
		"kind":  {Type: "string", Enum: []any{"a"}},
		"when":  {Type: "string", Format: "date-time"},
		"ref":   {Type: "string"},
	}}
	f, _, err := BuildFixture(context.Background(), notesModel(body, ClassSetupSafe), testAccounts[:1],
		[]SetupOp{{OperationID: "createNote"}}, d, testSecrets, "r1")
	if err != nil {
		t.Fatal(err)
	}
	o := f.Objects[0]
	if o.Protected["canary"] != "" || o.Public["confidence"] != "structural" {
		t.Fatalf("object: %+v", o)
	}
}

func TestBuildFixtureReturnsCreatedForCleanup(t *testing.T) {
	_, d := newToy(t)
	m := notesModel(freeTextBody(), ClassSetupSafe)
	_, created, err := BuildFixture(context.Background(), m, testAccounts,
		[]SetupOp{{OperationID: "createNote", Compensate: "deleteNote"}}, d, testSecrets, "r1")
	if err != nil {
		t.Fatal(err)
	}
	want := []CreatedObject{
		{Operation: "createNote", ID: "note-1", Owner: "cust-a", Compensate: "deleteNote"},
		{Operation: "createNote", ID: "note-2", Owner: "cust-b", Compensate: "deleteNote"},
	}
	for i := range want {
		if created[i] != want[i] {
			t.Fatalf("created[%d] = %+v", i, created[i])
		}
	}
}

func TestBuildFixtureRefusesUnclassifiedSetupOp(t *testing.T) {
	toy, d := newToy(t)
	for _, class := range []OpClass{ClassUnknown, ClassReversible} {
		m := notesModel(freeTextBody(), class)
		_, _, err := BuildFixture(context.Background(), m, testAccounts,
			[]SetupOp{{OperationID: "createNote"}}, d, testSecrets, "r1")
		if err == nil {
			t.Fatalf("class %s: expected error", class)
		}
	}
	_, _, err := BuildFixture(context.Background(), notesModel(freeTextBody(), ClassSetupSafe), testAccounts,
		[]SetupOp{{OperationID: "nope"}}, d, testSecrets, "r1")
	if err == nil {
		t.Fatal("missing op: expected error")
	}
	if toy.hits != 0 {
		t.Fatalf("%d requests sent", toy.hits)
	}
}

func TestBuildFixtureErrorsDoNotLeakToken(t *testing.T) {
	_, d := newToy(t)
	m := notesModel(freeTextBody(), ClassSetupSafe)
	m.Operations[0].Path = "/notes/{id}"
	m.Operations[0].PathParams = []Param{{Name: "id", In: "path"}}
	_, _, err := BuildFixture(context.Background(), m, testAccounts,
		[]SetupOp{{OperationID: "createNote"}}, d, testSecrets, "r1")
	if err == nil || strings.Contains(err.Error(), "tok-secret") {
		t.Fatalf("err = %v", err)
	}
}

func partialCase(t *testing.T, toy *toyNotes, d Doer, s SecretResolver) {
	m := notesModel(freeTextBody(), ClassSetupSafe)
	f, created, err := BuildFixture(context.Background(), m, testAccounts,
		[]SetupOp{{OperationID: "createNote", Compensate: "deleteNote"}}, d, s, "r1")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "tok-secret") {
		t.Fatalf("token leaked: %v", err)
	}
	want := CreatedObject{Operation: "createNote", ID: "note-1", Owner: "cust-a", Compensate: "deleteNote"}
	if len(created) != 1 || created[0] != want {
		t.Fatalf("created = %+v", created)
	}
	if len(f.Objects) != 1 || f.Objects[0].ID != "note-1" {
		t.Fatalf("fixture objects = %+v", f.Objects)
	}
}

func TestBuildFixturePartialOnSecondCreateFailure(t *testing.T) {
	toy, d := newToy(t)
	toy.failAt = 2
	partialCase(t, toy, d, testSecrets)
}

func TestBuildFixturePartialOnSecondResolveFailure(t *testing.T) {
	toy, d := newToy(t)
	partialCase(t, toy, d, mapSecrets{"ref/a": "tok-secret-a"})
}

func TestBuildFixturePartialOnMissingID(t *testing.T) {
	toy, d := newToy(t)
	toy.noID = 2
	partialCase(t, toy, d, testSecrets)
}
