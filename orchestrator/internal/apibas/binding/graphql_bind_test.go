package binding_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/binding"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/openapi"
	"github.com/audspect/bas/internal/apibas/runner"
)

const gqlSDL = `
type Query {
  order(id: ID!): Order
  orders(limit: Int, active: Boolean, status: Status): [Order!]!
  note(id: ID!): String
  byIds(ids: [ID!]!): Order
  filtered(f: Filter): Order
  find(term: String! = "x"): Order
  anything: Anything
}
type Order { id: ID! total: Float! secret: String customer: Customer }
type Customer { email: String }
enum Status { OPEN CLOSED }
input Filter { a: String }
union Anything = Order | Customer
type Mutation { setStatus(id: ID!): Order }
`

func gqlInventory(t *testing.T) *openapi.Inventory {
	t.Helper()
	inv, err := openapi.Import([]byte(gqlSDL))
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func gqlSpec() binding.Spec {
	return binding.Spec{
		Identities: []binding.IdentitySpec{{Name: "alice", CredentialRef: "shop/alice"}, {Name: "bob", CredentialRef: "shop/bob"}},
		Objects: []binding.ObjectSpec{
			{Operation: "QUERY /graphql#order", Params: map[string]string{"id": "ORD-A1"}, Owner: "alice", Selection: "id secret", ProtectedValues: []string{"alice-gql-secret"}},
			{Operation: "QUERY /graphql#order", Params: map[string]string{"id": "ORD-B1"}, Owner: "bob", Selection: "id secret", ProtectedValues: []string{"bob-gql-secret"}},
		},
	}
}

func TestGraphQLQueriesAreBoundAsPostRequestsWithTypedLiterals(t *testing.T) {
	plan, err := binding.Bind(gqlInventory(t), gqlSpec())
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if len(plan.Scenarios) != 2 || !plan.GraphQL || plan.Writes {
		t.Fatalf("plan: %d scenarios, graphql %v, writes %v", len(plan.Scenarios), plan.GraphQL, plan.Writes)
	}
	sc := plan.Scenarios[0]
	var body map[string]string
	if err := json.Unmarshal([]byte(sc.Steps[0].Body), &body); err != nil {
		t.Fatalf("the request body is not JSON: %v", err)
	}
	if body["query"] != `query { order(id: "ORD-A1") { id secret } }` {
		t.Errorf("query text: %q", body["query"])
	}
	if sc.Steps[0].Method != "POST" || sc.Steps[0].Path != "/graphql" || sc.Steps[1].Body != sc.Steps[0].Body || sc.Steps[0].Identity != "alice" || sc.Steps[1].Identity != "bob" {
		t.Errorf("steps: %+v", sc.Steps)
	}
	if !sc.CleanIsEnforced || !sc.RequireBaselineEvidence || sc.SideEffectClass != "READ_ONLY" || len(sc.ForbiddenValues) != 1 {
		t.Errorf("scenario: clean %v baseline evidence %v side effects %s forbidden %v", sc.CleanIsEnforced, sc.RequireBaselineEvidence, sc.SideEffectClass, sc.ForbiddenValues)
	}
	if !strings.Contains(strings.Join(plan.Limits, " "), "usually answers a refused query with HTTP 200") {
		t.Errorf("the limits do not explain how GraphQL denial is graded: %v", plan.Limits)
	}

	// Int, Boolean and enum arguments are written as their own literals, strings are quoted, and optional arguments may be left out.
	spec := gqlSpec()
	spec.Objects = []binding.ObjectSpec{
		{Operation: "QUERY /graphql#orders", Params: map[string]string{"limit": "5", "active": "true", "status": "OPEN"}, Owner: "alice", Selection: "id", ProtectedValues: []string{"alice-gql-secret"}},
		{Operation: "QUERY /graphql#orders", Params: map[string]string{}, Owner: "bob", Selection: "id customer { email }", ProtectedValues: []string{"bob-gql-secret"}},
		{Operation: "QUERY /graphql#note", Params: map[string]string{"id": "N-1"}, Owner: "alice", ProtectedValues: []string{"alice-note-value"}},
		{Operation: "QUERY /graphql#note", Params: map[string]string{"id": "N-2"}, Owner: "bob", ProtectedValues: []string{"bob-note-value"}},
	}
	plan, err = binding.Bind(gqlInventory(t), spec)
	if err != nil {
		t.Fatalf("Bind typed: %v", err)
	}
	want := []string{
		`query { orders(limit: 5, active: true, status: OPEN) { id } }`,
		`query { orders { id customer { email } } }`,
		`query { note(id: "N-1") }`,
		`query { note(id: "N-2") }`,
	}
	var got []string
	for _, sc := range plan.Scenarios {
		var b map[string]string
		_ = json.Unmarshal([]byte(sc.Steps[0].Body), &b)
		got = append(got, b["query"])
	}
	// Each operation binds one scenario per object whose owner has another identity to attack it.
	if len(got) != 4 {
		t.Fatalf("queries: %v", got)
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			found = found || g == w
		}
		if !found {
			t.Errorf("query %q not generated; got %v", w, got)
		}
	}
}

func TestGraphQLMutationsUnionsAndOldInventoriesAreSkippedWithReasons(t *testing.T) {
	spec := gqlSpec()
	spec.Objects = append(spec.Objects,
		binding.ObjectSpec{Operation: "MUTATION /graphql#setStatus", Params: map[string]string{"id": "ORD-A1"}, Owner: "alice"},
		binding.ObjectSpec{Operation: "QUERY /graphql#anything", Params: map[string]string{}, Owner: "alice"},
	)
	plan, err := binding.Bind(gqlInventory(t), spec)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	for op, want := range map[string]string{
		"MUTATION /graphql#setStatus": "only GraphQL queries are bound",
		"QUERY /graphql#anything":     "union",
	} {
		if got := skipReason(plan, op); !strings.Contains(got, want) {
			t.Errorf("%s: reason %q, want %q", op, got, want)
		}
	}
	// An inventory imported before argument types were recorded says to import the schema again.
	inv := gqlInventory(t)
	for i := range inv.Operations {
		inv.Operations[i].Returns, inv.Operations[i].Args = "", nil
	}
	if _, err := binding.Bind(inv, gqlSpec()); err == nil || !strings.Contains(err.Error(), "import the schema again") {
		t.Errorf("old inventory: %v", err)
	}
}

func TestGraphQLObjectValidation(t *testing.T) {
	base := func() binding.ObjectSpec {
		return binding.ObjectSpec{Operation: "QUERY /graphql#order", Params: map[string]string{"id": "ORD-A1"}, Owner: "alice", Selection: "id secret", ProtectedValues: []string{"alice-gql-secret"}}
	}
	mut := map[string]func(*binding.ObjectSpec){
		"missing argument":      func(o *binding.ObjectSpec) { o.Params = map[string]string{} },
		"unknown argument":      func(o *binding.ObjectSpec) { o.Params["other"] = "x1" },
		"quote in value":        func(o *binding.ObjectSpec) { o.Params["id"] = `a"b` },
		"no selection":          func(o *binding.ObjectSpec) { o.Selection = "" },
		"no protected value":    func(o *binding.ObjectSpec) { o.ProtectedValues = nil },
		"argument in selection": func(o *binding.ObjectSpec) { o.Selection = `secret(x: 1)` },
		"fragment":              func(o *binding.ObjectSpec) { o.Selection = "... on Order { id }" },
		"variable":              func(o *binding.ObjectSpec) { o.Selection = "$x" },
		"directive":             func(o *binding.ObjectSpec) { o.Selection = "id @skip" },
		"alias":                 func(o *binding.ObjectSpec) { o.Selection = "a: id" },
		"introspection":         func(o *binding.ObjectSpec) { o.Selection = "id __typename" },
		"empty braces":          func(o *binding.ObjectSpec) { o.Selection = "customer { }" },
		"unclosed":              func(o *binding.ObjectSpec) { o.Selection = "customer { email" },
		"stray close":           func(o *binding.ObjectSpec) { o.Selection = "id } {" },
		"starts with brace":     func(o *binding.ObjectSpec) { o.Selection = "{ id }" },
		"brace after brace":     func(o *binding.ObjectSpec) { o.Selection = "customer { { email } }" },
		"too deep":              func(o *binding.ObjectSpec) { o.Selection = "a { b { c { d { e { f { g } } } } } }" },
		"too long":              func(o *binding.ObjectSpec) { o.Selection = strings.Repeat("abcdefghij ", 60) },
		"too many parts":        func(o *binding.ObjectSpec) { o.Selection = strings.Repeat("a ", 130) },
		"query injection":       func(o *binding.ObjectSpec) { o.Selection = `id } } mutation { setStatus(id: "x") { id` },
		"selection on rest op": func(o *binding.ObjectSpec) {
			o.Operation = "QUERY /graphql#note"
			o.Params = map[string]string{"id": "N-1"}
		},
	}
	for name, f := range mut {
		o := base()
		o.Params = map[string]string{"id": "ORD-A1"}
		f(&o)
		spec := gqlSpec()
		spec.Objects = []binding.ObjectSpec{o}
		if _, err := binding.Bind(gqlInventory(t), spec); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Argument type rules.
	typed := map[string]binding.ObjectSpec{
		"bad Int":                {Operation: "QUERY /graphql#orders", Params: map[string]string{"limit": "five"}, Selection: "id", ProtectedValues: []string{"alice-gql-secret"}},
		"bad Boolean":            {Operation: "QUERY /graphql#orders", Params: map[string]string{"active": "yes"}, Selection: "id", ProtectedValues: []string{"alice-gql-secret"}},
		"bad enum":               {Operation: "QUERY /graphql#orders", Params: map[string]string{"status": "9x"}, Selection: "id", ProtectedValues: []string{"alice-gql-secret"}},
		"list given":             {Operation: "QUERY /graphql#byIds", Params: map[string]string{"ids": "A1"}, Selection: "id", ProtectedValues: []string{"alice-gql-secret"}},
		"input object":           {Operation: "QUERY /graphql#filtered", Params: map[string]string{"f": "x1"}, Selection: "id", ProtectedValues: []string{"alice-gql-secret"}},
		"required list left out": {Operation: "QUERY /graphql#byIds", Params: map[string]string{}, Selection: "id", ProtectedValues: []string{"alice-gql-secret"}},
	}
	for name, o := range typed {
		o.Owner = "alice"
		spec := gqlSpec()
		spec.Objects = []binding.ObjectSpec{o}
		if _, err := binding.Bind(gqlInventory(t), spec); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// An argument with a default may be left out, and a selection is refused on a REST operation.
	spec := gqlSpec()
	spec.Objects = []binding.ObjectSpec{
		{Operation: "QUERY /graphql#find", Params: map[string]string{}, Owner: "alice", Selection: "id", ProtectedValues: []string{"alice-gql-secret"}},
		{Operation: "QUERY /graphql#find", Params: map[string]string{"term": "t-1"}, Owner: "bob", Selection: "id", ProtectedValues: []string{"bob-gql-secret"}},
	}
	if _, err := binding.Bind(gqlInventory(t), spec); err != nil {
		t.Errorf("an argument with a default was required: %v", err)
	}
	rest := goodSpec()
	rest.Objects[0].Selection = "id"
	if _, err := binding.Bind(inventory(t), rest); err == nil {
		t.Error("a selection on a REST operation was accepted")
	}
}

func TestGraphQLSelectionIsReEmittedWithSingleSpaces(t *testing.T) {
	spec := gqlSpec()
	spec.Objects[0].Selection = "id,\n  customer{email}   secret"
	spec.Objects[1].Selection = "id"
	plan, err := binding.Bind(gqlInventory(t), spec)
	if err != nil {
		t.Fatal(err)
	}
	var b map[string]string
	_ = json.Unmarshal([]byte(plan.Scenarios[0].Steps[0].Body), &b)
	if b["query"] != `query { order(id: "ORD-A1") { id customer { email } secret } }` {
		t.Errorf("query: %q", b["query"])
	}
}

// gqlServer answers GraphQL queries the way real servers do: POST /graphql, a refusal is HTTP 200 with an errors entry.
func gqlServer(mode string) *httptest.Server {
	owners := map[string]string{"ORD-A1": "alice", "ORD-B1": "bob"}
	secrets := map[string]string{"ORD-A1": "alice-gql-secret", "ORD-B1": "bob-gql-secret"}
	tokens := map[string]string{"tok-alice": "alice", "tok-bob": "bob"}
	idRE := regexp.MustCompile(`order\(id: "([^"]+)"\)`)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /graphql", func(w http.ResponseWriter, r *http.Request) {
		who, ok := tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !ok {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Query string `json:"query"`
		}
		_ = json.Unmarshal(raw, &req)
		m := idRE.FindStringSubmatch(req.Query)
		w.Header().Set("Content-Type", "application/json")
		if mode == "broken" || m == nil {
			_, _ = w.Write([]byte(`{"errors":[{"message":"internal error"}]}`))
			return
		}
		id := m[1]
		if mode == "fixed" && owners[id] != who {
			_, _ = w.Write([]byte(`{"data":{"order":null},"errors":[{"message":"not authorized"}]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"order": map[string]string{"id": id, "secret": secrets[id]}}})
	})
	return httptest.NewServer(mux)
}

func runGQL(t *testing.T, mode string) []runner.Report {
	t.Helper()
	plan, err := binding.Bind(gqlInventory(t), gqlSpec())
	if err != nil {
		t.Fatal(err)
	}
	srv := gqlServer(mode)
	t.Cleanup(srv.Close)
	r, err := runner.New(runner.Config{BaseURL: srv.URL, Fixture: plan.Fixture,
		Secrets: runner.MapSecrets{"shop/alice": "tok-alice", "shop/bob": "tok-bob"}, State: runner.NoState{}})
	if err != nil {
		t.Fatal(err)
	}
	var out []runner.Report
	for _, s := range plan.Scenarios {
		rep, err := r.Run(context.Background(), s)
		if err != nil {
			t.Fatalf("%s: %v", s.ID, err)
		}
		out = append(out, rep)
	}
	return out
}

func TestGraphQLScenariosFindAMissingOwnerCheck(t *testing.T) {
	for _, rep := range runGQL(t, "vulnerable") {
		if rep.Outcome.Result != grade.FAIL || rep.Outcome.Exploitability != grade.Exploited {
			t.Errorf("%s against the vulnerable GraphQL API: %s %s (%s %s), want FAIL exploited", rep.ScenarioID, rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason, rep.Detail)
		}
	}
}

func TestGraphQLScenariosPassWhenARefusalIsAn200WithErrors(t *testing.T) {
	for _, rep := range runGQL(t, "fixed") {
		if rep.Outcome.Result != grade.PASS || rep.Outcome.Control != grade.Enforced {
			t.Errorf("%s against the fixed GraphQL API: %s %s (%s %s), want PASS enforced", rep.ScenarioID, rep.Outcome.Result, rep.Outcome.Control, rep.Outcome.Reason, rep.Detail)
		}
	}
}

// A server that answers every query with an error would look clean to the attacker too. The owner's own response must carry a
// protected value, so that case is SKIPPED, never a pass.
func TestGraphQLBaselineThatIsAnErrorIsSkippedNotPassed(t *testing.T) {
	for _, rep := range runGQL(t, "broken") {
		if rep.Outcome.Result != grade.SKIPPED || rep.Outcome.Reason != grade.ReasonPreconditionMissing {
			t.Errorf("%s with an erroring baseline: %s (%s %s), want SKIPPED PRECONDITION_MISSING", rep.ScenarioID, rep.Outcome.Result, rep.Outcome.Reason, rep.Detail)
		}
	}
}
