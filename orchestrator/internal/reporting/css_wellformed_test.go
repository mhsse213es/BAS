package reporting

import (
	"strings"
	"testing"
)

// stripCSSComments removes /* ... */ comments with a state machine. A regex is
// not good enough here: the stylesheet's comments quote CSS at length, braces
// and all.
func stripCSSComments(css string) (out string, unterminated bool) {
	var b strings.Builder
	for i := 0; i < len(css); {
		if strings.HasPrefix(css[i:], "/*") {
			j := strings.Index(css[i+2:], "*/")
			if j < 0 {
				return b.String(), true
			}
			i += 2 + j + 2
			continue
		}
		b.WriteByte(css[i])
		i++
	}
	return b.String(), false
}

func reportStylesheet(t *testing.T) string {
	t.Helper()
	start := strings.Index(reportHTML, "<style>")
	end := strings.Index(reportHTML, "</style>")
	if start < 0 || end < 0 || end < start {
		t.Fatal("could not locate the <style> block in the report template")
	}
	return reportHTML[start+len("<style>") : end]
}

// An unterminated comment silently swallows every rule up to the next "*/".
// This has bitten twice while editing the print rules: once it commented out
// the running-footer declaration, and the symptom was not a parse error but a
// rule that simply never applied, which reads exactly like a cascade problem
// and sends you debugging the wrong thing.
func TestReportCSS_CommentsAreTerminated(t *testing.T) {
	css := reportStylesheet(t)
	if _, unterminated := stripCSSComments(css); unterminated {
		// Point at the offender: the last opener with no closer after it.
		idx := strings.LastIndex(css, "/*")
		snippet := css[idx:]
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		t.Fatalf("unterminated CSS comment — everything after it is swallowed.\nStarts: %s", snippet)
	}
}

// Brace balance, checked on the comment-stripped stylesheet. An extra or
// missing brace silently reparents rules into (or out of) a media block.
func TestReportCSS_BracesBalance(t *testing.T) {
	css, unterminated := stripCSSComments(reportStylesheet(t))
	if unterminated {
		t.Skip("comment terminator test covers this")
	}
	depth := 0
	for i := 0; i < len(css); i++ {
		switch css[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth < 0 {
				t.Fatalf("unbalanced '}' at offset %d — a rule closed a block it never opened", i)
			}
		}
	}
	if depth != 0 {
		t.Errorf("stylesheet ends %d block(s) deep; every @media and rule must close", depth)
	}
}

// The running classification footer must stay wired up: the markup present, and
// the tfoot declared visible OUTSIDE @media print. Declaring it inside the print
// block is what the first two attempts did, and it is fragile — the surrounding
// comment ate it once already.
func TestReportCSS_RunningFooterIsWired(t *testing.T) {
	if !strings.Contains(reportHTML, `<table class="runsheet">`) {
		t.Error("the .runsheet wrapper table is gone; the classification bar cannot repeat per sheet without it")
	}
	if !strings.Contains(reportHTML, "<tfoot>") {
		t.Error("the runsheet tfoot is gone; Chrome repeats and reserves space for the bar via the table footer group")
	}
	css, _ := stripCSSComments(reportStylesheet(t))
	if !strings.Contains(css, ".runsheet>tfoot{display:table-footer-group}") {
		t.Error("the tfoot is not declared display:table-footer-group in live CSS (commented out, or moved into a media block)")
	}
	if !strings.Contains(css, "@media screen{.runsheet>tfoot{display:none}}") {
		t.Error("the screen override is missing; the bar would print inside the on-screen card too")
	}
}
