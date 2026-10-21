package detect

import "testing"

// REL-014: a page request above the documented maximum fires whatever the outcome. The maximum itself does not.
func TestRel014PageSizeAboveMaximum(t *testing.T) {
	cases := []struct {
		name string
		size int
		want bool
	}{
		{"no page size named", 0, false},
		{"at the maximum", MaxPageSize, false},
		{"one above the maximum", MaxPageSize + 1, true},
		{"far above the maximum", 100000, true},
	}
	for _, c := range cases {
		ev := Event{Seq: 1, CorrelationID: "run", Action: "GET /api/orders/page", Outcome: "failure", Status: 400,
			Identity: "cust-b", PageSize: c.size}
		if got := hasRule(evaluate([]Event{ev}, ElasticRules, "run", SourceElastic), "APIBAS-REL-014"); got != c.want {
			t.Errorf("%s: REL-014 = %v, want %v", c.name, got, c.want)
		}
	}
}

// REL-015: a body above the documented upload ceiling fires whatever the outcome. The ceiling itself does not.
func TestRel015RequestBytesAboveCeiling(t *testing.T) {
	cases := []struct {
		name  string
		bytes int64
		want  bool
	}{
		{"small body", 64, false},
		{"at the ceiling", MaxRequestBytes, false},
		{"one byte above the ceiling", MaxRequestBytes + 1, true},
	}
	for _, c := range cases {
		ev := Event{Seq: 1, CorrelationID: "run", Action: "POST /api/orders/ORD-2001/attachments", Outcome: "failure",
			Status: 413, Identity: "cust-b", RequestBytes: c.bytes}
		if got := hasRule(evaluate([]Event{ev}, ElasticRules, "run", SourceElastic), "APIBAS-REL-015"); got != c.want {
			t.Errorf("%s: REL-015 = %v, want %v", c.name, got, c.want)
		}
	}
}

// REL-016: an owner's response marked public fires. A private or no-store response does not, and neither does an
// unowned or refused one.
func TestRel016OwnerDataPubliclyCacheable(t *testing.T) {
	owned := []string{"cust-b"}
	cases := []struct {
		name string
		ev   Event
		want bool
	}{
		{"owner data, public cache", Event{Status: 200, Outcome: "success", ObjectOwner: "cust-b", ObjectOwners: owned,
			CacheControl: "public, max-age=300"}, true},
		{"owner data, private no-store", Event{Status: 200, Outcome: "success", ObjectOwner: "cust-b", ObjectOwners: owned,
			CacheControl: "private, no-store"}, false},
		{"owner data, no cache header", Event{Status: 200, Outcome: "success", ObjectOwner: "cust-b", ObjectOwners: owned}, false},
		{"public cache, refused", Event{Status: 401, Outcome: "failure", ObjectOwner: "cust-b", ObjectOwners: owned,
			CacheControl: "public"}, false},
		{"public cache, no owned object", Event{Status: 200, Outcome: "success", CacheControl: "public"}, false},
	}
	for _, c := range cases {
		c.ev.Seq, c.ev.CorrelationID, c.ev.Action, c.ev.Identity = 1, "run", "GET /api/orders/ORD-2001/status", "cust-b"
		if got := hasRule(evaluate([]Event{c.ev}, ElasticRules, "run", SourceElastic), "APIBAS-REL-016"); got != c.want {
			t.Errorf("%s: REL-016 = %v, want %v", c.name, got, c.want)
		}
	}
}
