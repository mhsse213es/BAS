package runner_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// ABUSE-003 runs on the paged fixture: the owner holds 151 orders, more than the
// largest page the fixed build allows, so both the granted size and the item count
// can exceed the cap.
func TestPhase12_PaginationVulnerableFailsFixedPasses(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersPaged())
	rep := e.run(t, scenarioByID(t, "API-BAS-ABUSE-003"), e.state)
	if rep.Outcome.Result != grade.FAIL || rep.Outcome.Exploitability != grade.Exploited {
		t.Fatalf("vulnerable got %s / %s (%s), want FAIL / exploited",
			rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason)
	}

	e = newEnv(t, lab.ModeFixed, fixture.OrdersPaged())
	rep = e.run(t, scenarioByID(t, "API-BAS-ABUSE-003"), e.state)
	if rep.Outcome.Result != grade.PASS || rep.Outcome.Control != grade.Enforced {
		t.Fatalf("fixed got %s / %s (%s), want PASS / enforced",
			rep.Outcome.Result, rep.Outcome.Control, rep.Outcome.Reason)
	}
	if attack := rep.Exchanges[len(rep.Exchanges)-1]; attack.Status != http.StatusBadRequest {
		t.Fatalf("fixed oversized page status = %d, want 400", attack.Status)
	}
}

// The owner holds 151 orders (ORD-2001 and ORD-P001..P150), so a page request can name more items than the
// cap. These checks read the lab directly, because the report keeps only the first 2 KiB of each body.
// Expectations: the vulnerable build returns all 151 items for limit=100000; the fixed build refuses that limit
// with 400, and for limit=100 returns exactly the cap of 100 items.
func TestPhase12_ItemCountFromLab(t *testing.T) {
	for _, c := range []struct {
		mode       lab.Mode
		limit      string
		wantStatus int
		wantItems  int
	}{
		{lab.ModeVulnerable, "100000", http.StatusOK, 151},
		{lab.ModeFixed, "100000", http.StatusBadRequest, 0},
		{lab.ModeFixed, "100", http.StatusOK, 100},
	} {
		e := newEnv(t, c.mode, fixture.OrdersPaged())
		tok := e.secrets["apibas/lab/customer-b"]
		if tok == "" {
			t.Fatal("customer-b token not in secrets")
		}
		req, err := http.NewRequest(http.MethodGet, e.url+"/api/orders/page?limit="+c.limit, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			Items []json.RawMessage `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode != c.wantStatus || len(body.Items) != c.wantItems {
			t.Fatalf("%s limit=%s: status %d items %d, want %d and %d",
				modeName(c.mode), c.limit, resp.StatusCode, len(body.Items), c.wantStatus, c.wantItems)
		}
	}
}
