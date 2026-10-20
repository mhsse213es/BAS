package protocol

import (
	"strings"
	"testing"
)

func TestParseGraphQLAcceptsSelectionsAndArguments(t *testing.T) {
	doc, err := ParseGraphQL(`{ order(id: "ORD-2001") { id status } }`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Fields) != 1 || doc.Fields[0].Name != "order" {
		t.Fatalf("root fields = %+v, want one order field", doc.Fields)
	}
	if got := doc.Fields[0].Args["id"]; got != "ORD-2001" {
		t.Fatalf("id argument = %q, want ORD-2001", got)
	}
	if len(doc.Fields[0].Sub) != 2 {
		t.Fatalf("order selections = %d, want 2", len(doc.Fields[0].Sub))
	}
}

func TestParseGraphQLAcceptsOperationKeyword(t *testing.T) {
	if _, err := ParseGraphQL(`query Q { order(id: "ORD-2001") { id } }`); err != nil {
		t.Fatalf("named query rejected: %v", err)
	}
}

func TestParseGraphQLDepth(t *testing.T) {
	shallow, err := ParseGraphQL(`{ order(id: "x") { id status } }`)
	if err != nil {
		t.Fatalf("shallow: %v", err)
	}
	if d := shallow.Depth(); d != 2 {
		t.Fatalf("shallow depth = %d, want 2", d)
	}
	deep, err := ParseGraphQL(`{ order(id: "x") { items { order { items { order { items { id } } } } } } }`)
	if err != nil {
		t.Fatalf("deep: %v", err)
	}
	if d := deep.Depth(); d <= 3 {
		t.Fatalf("deep depth = %d, want more than 3", d)
	}
}

// Malformed queries are refused by the adapter before they are sent.
func TestParseGraphQLRefusesMalformed(t *testing.T) {
	cases := map[string]string{
		"unbalanced brace":   `{ order(id: "x") { id }`,
		"empty selection":    `{ order(id: "x") { } }`,
		"fragment spread":    `{ order(id: "x") { ...F } }`,
		"missing argument":   `{ order(id: ) { id } }`,
		"unterminated value": `{ order(id: "x) { id } }`,
		"trailing garbage":   `{ id } extra`,
		"empty":              ``,
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseGraphQL(q); err == nil {
				t.Fatalf("query %q was accepted, want an error", q)
			}
		})
	}
}

func TestGraphQLValidateBody(t *testing.T) {
	g := GraphQL{}
	if err := g.Validate(`{"query": "{ order(id: \"ORD-2001\") { id } }"}`); err != nil {
		t.Fatalf("valid body refused: %v", err)
	}
	if err := g.Validate(`not json`); err == nil {
		t.Fatal("non-JSON body accepted")
	}
	if err := g.Validate(`{"query": ""}`); err == nil {
		t.Fatal("empty query accepted")
	}
	if err := g.Validate(`{"query": "{ id "}`); err == nil {
		t.Fatal("malformed query accepted")
	}
}

func TestGraphQLIsRegisteredAndOthersAreNot(t *testing.T) {
	if !Supported("graphql") {
		t.Fatal("graphql has an adapter but Supported reports false")
	}
	for _, p := range []string{"websocket", "async"} {
		if Supported(p) {
			t.Fatalf("%s reported supported with no adapter", p)
		}
	}
	if !strings.Contains(strings.Join(Names(), ","), "graphql") {
		t.Fatalf("Names() = %v, want graphql", Names())
	}
}
