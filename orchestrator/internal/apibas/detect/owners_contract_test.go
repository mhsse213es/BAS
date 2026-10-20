package detect

import "testing"

// Expected results are written from the rule before the cases run.
// Foreign ownership holds when any named owner differs from the caller. The first owner is not the whole story.

func TestForeignOwnershipReadsEverySecondOwner(t *testing.T) {
	// The caller cust-a names its own order first, then a foreign order owned by cust-b.
	e := Event{Seq: 1, CorrelationID: "r", Action: "PATCH /api/orders/bulk", Outcome: "success",
		Identity: "cust-a", Status: 200, ObjectOwner: "cust-a", ObjectOwners: []string{"cust-a", "cust-b"}}
	if !foreignOwned(e) {
		t.Fatal("a foreign second owner must count as foreign ownership")
	}
}

func TestREL004SingleOwnerKeepsItsMeaning(t *testing.T) {
	own := Event{Identity: "cust-a", ObjectOwner: "cust-a"}
	other := Event{Identity: "cust-a", ObjectOwner: "cust-b"}
	none := Event{Identity: "cust-a"}
	if foreignOwned(own) || !foreignOwned(other) || foreignOwned(none) {
		t.Fatalf("single-owner meaning changed: own=%v other=%v none=%v",
			foreignOwned(own), foreignOwned(other), foreignOwned(none))
	}
}

func TestValidateRejectsMismatchedFirstOwner(t *testing.T) {
	e := Event{Seq: 1, CorrelationID: "r", Action: "GET /x", Outcome: "success", Identity: "cust-a",
		Status: 200, ObjectOwner: "cust-b", ObjectOwners: []string{"cust-a", "cust-b"}}
	if err := e.Validate(); err == nil {
		t.Fatal("object_owner must equal object_owners[0]")
	}
}
