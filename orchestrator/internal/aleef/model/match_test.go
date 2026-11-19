package model

import "testing"

func matchModel() Model {
	return Model{Operations: []Operation{
		{ID: "get", Method: "GET", Path: "/api/items/{id}"},
		{ID: "list", Method: "GET", Path: "/api/items"},
		{ID: "pay", Method: "POST", Path: "/api/items/{id}/pay"},
		{ID: "payAny", Method: "POST", Path: "/api/items/{x}/{y}"},
	}}
}

func opIDs(ops []Operation) []string {
	var o []string
	for _, p := range ops {
		o = append(o, p.ID)
	}
	return o
}

func TestMatchTemplates(t *testing.T) {
	m := matchModel()
	if got := opIDs(m.Match("GET", "/api/items/42")); len(got) != 1 || got[0] != "get" {
		t.Fatalf("got %v", got)
	}
	if got := opIDs(m.Match("get", "/api/items")); len(got) != 1 || got[0] != "list" {
		t.Fatalf("method must be case-insensitive: %v", got)
	}
	if got := opIDs(m.Match("POST", "/api/items/42/pay")); len(got) != 2 {
		t.Fatalf("overlapping templates must both match: %v", got)
	}
}

func TestMatchIsStrict(t *testing.T) {
	m := matchModel()
	for _, p := range []string{"/API/items/42", "/api/items/42/extra/more", "/api", "/other"} {
		if got := m.Match("GET", p); len(got) != 0 {
			t.Fatalf("%s matched %v", p, opIDs(got))
		}
	}
	if got := m.Match("DELETE", "/api/items/42"); len(got) != 0 {
		t.Fatalf("wrong method matched %v", opIDs(got))
	}
	if got := m.Match("GET", "/api/items//"); len(got) != 0 && opIDs(got)[0] == "get" {
		t.Fatalf("empty segment must not satisfy a placeholder: %v", opIDs(got))
	}
	if PathMatches("/a/{id}", "/a/") {
		t.Fatal("empty segment matched placeholder")
	}
}
