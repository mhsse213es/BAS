package property

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/runner"
)

func TestIdemTemplatesDetectToyDoubleProcess(t *testing.T) {
	// P-IDEM-1: the key is ignored, so a replay creates a second record.
	ty, srv := newToy("idem-ignore")
	defer srv.Close()
	tpls := templatesFor(t, "P-IDEM-1", "invoice", nil)
	if len(tpls) != 1 {
		t.Fatalf("want 1 template, got %d", len(tpls))
	}
	expect(t, ty, srv, tpls, grade.FAIL)

	// Corrected: the replay returns the stored response, no new record.
	ok, srvOK := newToy()
	defer srvOK.Close()
	expect(t, ok, srvOK, tpls, grade.PASS)

	// Structure: baseline read, setup with the key, attack with the same key.
	s := tpls[0].Steps
	if len(s) != 3 || s[1].Headers[IdempotencyHeader] == "" || s[1].Headers[IdempotencyHeader] != s[2].Headers[IdempotencyHeader] {
		t.Fatalf("bad replay chain: %+v", s)
	}
	if s[1].Body != s[2].Body {
		t.Fatal("P-IDEM-1 must replay the identical body")
	}
}

func TestIdemKeyReuseWithDifferentBody(t *testing.T) {
	ty, srv := newToy("idem-nobody")
	defer srv.Close()
	tpls := templatesFor(t, "P-IDEM-2", "invoice", nil)
	if len(tpls) != 1 {
		t.Fatalf("want 1 template, got %d", len(tpls))
	}
	if tpls[0].Steps[1].Body == tpls[0].Steps[2].Body {
		t.Fatal("P-IDEM-2 must change the body")
	}
	expect(t, ty, srv, tpls, grade.FAIL)

	ok, srvOK := newToy()
	defer srvOK.Close()
	expect(t, ok, srvOK, tpls, grade.PASS)
}

func TestIdemNeedsClassifiedPostWithVaryingBody(t *testing.T) {
	if got := templatesFor(t, "P-IDEM-1", "getV2", nil); len(got) != 0 {
		t.Fatal("a read is not an idempotency target")
	}
	// A body-less POST cannot vary, so P-IDEM-2 has nothing to test.
	got := templatesFor(t, "P-IDEM-2", "invoice", func(c *TemplateCtx) { c.Op.Body = nil })
	if len(got) != 0 {
		t.Fatal("no body to vary: P-IDEM-2 must emit nothing")
	}
	got = templatesFor(t, "P-IDEM-1", "invoice", func(c *TemplateCtx) { c.Op.Class = "unknown" })
	if len(got) != 0 {
		t.Fatal("unclassified operations must emit nothing")
	}
}

func attackResponses(rep runner.Report) []Response {
	var rs []Response
	for _, e := range rep.Exchanges[1:] { // exchange 0 is the baseline
		rs = append(rs, Response{Status: e.Status, Body: []byte(e.Body)})
	}
	return rs
}

func TestRaceTemplatesDetectToyLimitBreach(t *testing.T) {
	tpls := templatesFor(t, "P-RACE-1", "redeem", nil)
	if len(tpls) != 1 {
		t.Fatalf("want 1 template, got %d", len(tpls))
	}
	a := tpls[0].Steps[len(tpls[0].Steps)-1]
	if !a.Parallel || a.Repeat < 2 || tpls[0].MaxAccepted != 1 {
		t.Fatalf("bad race shape: %+v max=%d", a, tpls[0].MaxAccepted)
	}

	// Check-then-act race, state adapter that does not report the permitted effect.
	ty, srv := newToy("race")
	defer srv.Close()
	ty.hideRedeem = true
	expect(t, ty, srv, tpls, grade.FAIL)
	if rep := run(t, ty, srv, tpls[0]); !tpls[0].ExceedsLimit(attackResponses(rep)) {
		t.Fatal("ExceedsLimit must see the breach")
	}

	// Corrected: one success, the rest refused.
	ok, srvOK := newToy()
	defer srvOK.Close()
	ok.hideRedeem = true
	expect(t, ok, srvOK, tpls, grade.PASS)

	// With a state adapter that reports the permitted effect the runner grades
	// FAIL even though the limit held (documented limitation); ExceedsLimit is
	// the decisive oracle and says the limit held.
	ok.hideRedeem = false
	rep := run(t, ok, srvOK, tpls[0])
	if rep.Outcome.Result != grade.FAIL {
		t.Fatalf("expected the documented runner false positive, got %s", rep.Outcome.Result)
	}
	if tpls[0].ExceedsLimit(attackResponses(rep)) {
		t.Fatal("limit held: ExceedsLimit must be false")
	}
	if tpls[0].Params["oracle"] != "accepted_over_limit" {
		t.Fatal("template must name its decisive oracle")
	}
}

func TestRaceLimitDeclarations(t *testing.T) {
	// A reversible operation is not once-only by nature: it needs a declared limit.
	if got := templatesFor(t, "P-RACE-1", "patchV2", nil); len(got) != 0 {
		t.Fatal("reversible op without a declared limit must emit nothing")
	}
	got := templatesFor(t, "P-RACE-1", "patchV2", func(c *TemplateCtx) { c.Limits = map[string]int{"patchV2": 2} })
	if len(got) != 1 || got[0].MaxAccepted != 2 || got[0].Steps[len(got[0].Steps)-1].Repeat != 6 {
		t.Fatalf("declared limit 2 must give max_accepted 2 and 6 requests: %+v", got)
	}
}
