package openapi

import (
	"encoding/json"
	"reflect"
	"testing"
)

func inv(ops ...Operation) *Inventory { return &Inventory{Operations: ops} }

func TestCompare(t *testing.T) {
	old := inv(
		Operation{Method: "GET", Path: "/a", Auth: AuthRequired},
		Operation{Method: "GET", Path: "/b", Auth: AuthRequired},
		Operation{Method: "GET", Path: "/c", Auth: AuthRequired},
	)
	next := inv(
		Operation{Method: "GET", Path: "/a", Auth: AuthRequired},
		Operation{Method: "GET", Path: "/b", Auth: AuthNone}, // lost its authentication
		Operation{Method: "POST", Path: "/d", Auth: AuthRequired},
	)
	got := Compare(old, next)
	if !reflect.DeepEqual(got.Added, []string{"POST /d"}) || !reflect.DeepEqual(got.Removed, []string{"GET /c"}) {
		t.Errorf("added %v removed %v", got.Added, got.Removed)
	}
	if len(got.AuthChanged) != 1 || got.AuthChanged[0] != (AuthChange{"GET /b", AuthRequired, AuthNone}) {
		t.Errorf("auth changed %v", got.AuthChanged)
	}
	if got.Empty() {
		t.Error("Empty reported true for a real change")
	}
	if !Compare(next, next).Empty() {
		t.Error("an inventory differs from itself")
	}
	if first := Compare(nil, next); len(first.Added) != 3 {
		t.Errorf("with no earlier inventory every operation is added: %v", first.Added)
	}
}

// The inventory is stored as JSON, so it must survive a round trip with its classes and authentication intact.
func TestInventoryJSONRoundTrip(t *testing.T) {
	in := load(t)
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Inventory
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in.Operations, out.Operations) || in.Title != out.Title {
		t.Error("the inventory changed through JSON")
	}
}
