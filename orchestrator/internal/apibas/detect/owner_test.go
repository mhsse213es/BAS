package detect

import "testing"

func ownedEvent(seq int, identity, owner, outcome string, status int) Event {
	e := ev(seq, "c", outcome, status)
	e.Identity = identity
	e.ObjectOwner = owner
	return e
}

// An attempt against another identity's object fires the cross-identity rule, whether
// the attempt succeeded or was denied.
func TestCrossIdentityFiresOnDeniedAndAllowed(t *testing.T) {
	for _, outcome := range []struct {
		name   string
		status int
		out    string
	}{{"allowed", 200, "success"}, {"denied", 403, "failure"}} {
		f := NewElasticFixture()
		if err := f.Ingest([]Event{ownedEvent(1, "customer-a", "customer-b", outcome.out, outcome.status)}); err != nil {
			t.Fatal(err)
		}
		if got := Grade(f.Alerts("c"), "APIBAS-REL-004", SeverityHigh, "c"); got != "detected" {
			t.Errorf("%s cross-identity attempt = %s, want detected", outcome.name, got)
		}
	}
}

// The owner reading their own object is not cross-identity.
func TestOwnerAccessDoesNotFireCrossIdentity(t *testing.T) {
	f := NewElasticFixture()
	_ = f.Ingest([]Event{ownedEvent(1, "customer-b", "customer-b", "success", 200)})
	if got := Grade(f.Alerts("c"), "APIBAS-REL-004", SeverityHigh, "c"); got != "not_detected" {
		t.Fatalf("owner access = %s, want not_detected", got)
	}
}

// Requests that name no order carry no owner and never fire the rule.
func TestNoOwnerNeverFiresCrossIdentity(t *testing.T) {
	f := NewElasticFixture()
	_ = f.Ingest([]Event{ownedEvent(1, "customer-a", "", "success", 200)})
	if got := Grade(f.Alerts("c"), "APIBAS-REL-004", SeverityHigh, "c"); got != "not_detected" {
		t.Fatalf("event with no owner = %s, want not_detected", got)
	}
}
