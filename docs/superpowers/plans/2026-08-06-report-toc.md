# Clickable Table of Contents for the BAS Assessment Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the BAS Security Assessment Report a visible, clickable table-of-contents page (in both the HTML view and the PDF), plus a native PDF reader bookmark sidebar — for per-run reports, campaign reports, and the audit-pack's `executive-report.pdf`, since they all share `GenerateHTML`'s output.

**Architecture:** After `reportTmpl.Execute` renders the report to a buffer (every `{{if}}` already resolved, so only real, present-in-this-report sections remain), a new post-processing pass regex-scans the buffer for the report's existing, uniform `Section N` / title marker pattern, stamps an anchor `id` on each one, and inserts a new linked TOC page right after the cover. Separately, Chrome's native `GenerateDocumentOutline` PDF flag is enabled, fed by `role="heading"` hints added to the section-title markup.

**Tech Stack:** Go `regexp` (stdlib), `html/template` (existing), `chromedp`/`cdproto` (existing, `github.com/chromedp/cdproto v0.0.0-20260321001828-e3e3800016bc`).

## Global Constraints

- Scope: `orchestrator/internal/reporting/html.go` (`GenerateHTML`, the `reportHTML` template) and `orchestrator/internal/reporting/htmlpdf.go` only. The separate Exercise/Purple-Team report (`exercise.go`) is explicitly out of scope.
- No page numbers in TOC entries — click-to-jump links only (page numbers aren't knowable at HTML-generation time; see spec's Non-goals).
- No restructuring of `reportHTML`'s existing ~20 sections' conditional logic — the TOC is built entirely from the template's already-rendered output.
- `GenerateHTML`'s public signature (`func GenerateHTML(w io.Writer, r *FullReport, compliance []ComplianceSummaryRow) error`) does not change — all 5 existing callers are unaffected.

---

### Task 1: `injectTableOfContents` — extraction, id-stamping, TOC page, and its CSS

**Files:**
- Create: `orchestrator/internal/reporting/toc.go`
- Test: `orchestrator/internal/reporting/toc_test.go`
- Modify: `orchestrator/internal/reporting/html.go:668-669` (insert `.toc-list`/`.toc-item` CSS into the existing `<style>` block, between the `h1{...}` rule ending at line 668 and the `h2{...}` rule at line 669 — no other change to html.go in this task)

**Interfaces:**
- Produces: `func injectTableOfContents(html []byte) []byte` — Task 2 calls this from `GenerateHTML`.
- Produces (unexported, used only within `toc.go`): `tocEntry{Number, Title, ID string}`, `sectionMarker *regexp.Regexp`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/reporting/toc_test.go`:

```go
package reporting

import (
	"strings"
	"testing"
)

func TestInjectTableOfContents_ExtractsSectionsInOrder(t *testing.T) {
	html := `<div class="page"><div class="stag">Section 1</div><div class="stitle">Executive Summary</div></div>` +
		`<div class="page"><div class="stag">Section 2</div><div class="stitle">MITRE ATT&amp;CK Tactic Summary</div></div>` +
		`<div class="page"><div class="stag">Section 3</div><div class="stitle">Action Plan</div></div>`

	out := string(injectTableOfContents([]byte(html)))

	for _, id := range []string{`id="sec-1"`, `id="sec-2"`, `id="sec-3"`} {
		if !strings.Contains(out, id) {
			t.Errorf("output missing %s", id)
		}
	}
	for _, href := range []string{`href="#sec-1"`, `href="#sec-2"`, `href="#sec-3"`} {
		if !strings.Contains(out, href) {
			t.Errorf("TOC missing link %s", href)
		}
	}
	// Entity must survive verbatim, not be double-escaped (e.g. not "&amp;amp;").
	if !strings.Contains(out, "MITRE ATT&amp;CK Tactic Summary") {
		t.Error("TOC entry title lost or double-escaped the &amp; entity")
	}
	if strings.Contains(out, "&amp;amp;") {
		t.Error("TOC entry title was double-escaped")
	}
	// Order: sec-1's id must appear before sec-2's, before sec-3's.
	i1, i2, i3 := strings.Index(out, `id="sec-1"`), strings.Index(out, `id="sec-2"`), strings.Index(out, `id="sec-3"`)
	if !(i1 < i2 && i2 < i3) {
		t.Errorf("section ids out of order: sec-1=%d sec-2=%d sec-3=%d", i1, i2, i3)
	}
}

func TestInjectTableOfContents_SubLetterSections(t *testing.T) {
	html := `<div class="page"><div class="stag">Section 10a</div><div class="stitle">Ransomware Readiness</div></div>` +
		`<div class="page"><div class="stag">Section 10b</div><div class="stitle">EPSS Priority Index</div></div>`

	out := string(injectTableOfContents([]byte(html)))

	if !strings.Contains(out, `id="sec-10a"`) {
		t.Error("output missing id=\"sec-10a\"")
	}
	if !strings.Contains(out, `id="sec-10b"`) {
		t.Error("output missing id=\"sec-10b\"")
	}
	if !strings.Contains(out, `href="#sec-10a"`) || !strings.Contains(out, `href="#sec-10b"`) {
		t.Error("TOC missing links to sub-lettered sections")
	}
}

func TestInjectTableOfContents_NoSections_ReturnsUnchanged(t *testing.T) {
	html := `<div class="page"><p>No sections here.</p></div>`

	out := injectTableOfContents([]byte(html))

	if string(out) != html {
		t.Errorf("expected unchanged output, got %q", string(out))
	}
}

func TestInjectTableOfContents_InsertsAfterCover(t *testing.T) {
	html := `<div class="page"><div class="cover">cover content</div></div>` + "\n\n" +
		`<!-- ═══ 1. EXECUTIVE SUMMARY ════════════════════════════════════════════ -->` + "\n" +
		`<div class="page"><div class="stag">Section 1</div><div class="stitle">Executive Summary</div></div>`

	out := string(injectTableOfContents([]byte(html)))

	coverEnd := strings.Index(out, "cover content") + len("cover content")
	tocIdx := strings.Index(out, "Table of Contents")
	commentIdx := strings.Index(out, "EXECUTIVE SUMMARY")

	if tocIdx == -1 {
		t.Fatal("TOC page not found in output")
	}
	if !(coverEnd < tocIdx && tocIdx < commentIdx) {
		t.Errorf("TOC page not positioned between cover (ends %d) and first section comment (%d): TOC at %d", coverEnd, commentIdx, tocIdx)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestInjectTableOfContents -v`
Expected: FAIL with "undefined: injectTableOfContents"

- [ ] **Step 3: Implement `toc.go`**

```go
package reporting

import (
	"bytes"
	"regexp"
	"strings"
)

// sectionMarker matches one section's stag/stitle pair in fully-rendered
// report HTML -- after every {{if}} in reportHTML has already resolved, so
// this only ever sees sections that actually appear in this specific
// report. Every section in reportHTML uses this exact, attribute-free
// shape with zero deviation (verified by grep across the whole template).
var sectionMarker = regexp.MustCompile(`<div class="stag">Section ([^<]+)</div>\s*<div class="stitle">([^<]+)</div>`)

// coverBoundary is the literal comment that immediately precedes the first
// content section in reportHTML (html.go), used to find where the cover
// page ends. If ever not found (defensive -- the template always contains
// it today), injectTableOfContents falls back to inserting before the
// first matched section instead.
const coverBoundary = "<!-- ═══ 1."

// tocEntry is one row of the extracted table of contents.
type tocEntry struct {
	Number string // e.g. "1", "10a", "11" -- raw text between the stag tags
	Title  string // raw HTML text between the stitle tags, may contain entities like "&amp;"
	ID     string // anchor id, e.g. "sec-10a"
}

// injectTableOfContents scans rendered report HTML for section markers,
// stamps an id onto each one, and inserts a new table-of-contents page
// immediately after the cover page. Returns html unchanged if no sections
// are found.
func injectTableOfContents(html []byte) []byte {
	matches := sectionMarker.FindAllSubmatchIndex(html, -1)
	if len(matches) == 0 {
		return html
	}

	entries := make([]tocEntry, len(matches))
	for i, m := range matches {
		number := string(html[m[2]:m[3]])
		title := string(html[m[4]:m[5]])
		entries[i] = tocEntry{
			Number: number,
			Title:  title,
			ID:     "sec-" + strings.ToLower(strings.TrimSpace(number)),
		}
	}

	// Rewrite: stamp id="sec-N" onto each matched <div class="stag"> opening
	// tag, built from match indices so we never re-match against
	// already-modified text.
	var rewritten bytes.Buffer
	last := 0
	for i, m := range matches {
		rewritten.Write(html[last:m[0]])
		rewritten.WriteString(`<div class="stag" id="` + entries[i].ID + `">Section ` + entries[i].Number + `</div>`)
		rewritten.WriteString(`<div class="stitle" role="heading" aria-level="1">` + entries[i].Title + `</div>`)
		last = m[1]
	}
	rewritten.Write(html[last:])
	out := rewritten.Bytes()

	tocPage := renderTOCPage(entries)

	insertAt := bytes.Index(out, []byte(coverBoundary))
	if insertAt == -1 {
		// Defensive fallback: insert right before the first matched section.
		// Match offsets shifted by the id/role-attribute insertions above, so
		// re-find the first section's start in the rewritten buffer.
		firstSection := sectionMarker.FindIndex(out)
		if firstSection == nil {
			return out // shouldn't happen (matches was non-empty), but never panic
		}
		insertAt = firstSection[0]
	}

	var final bytes.Buffer
	final.Write(out[:insertAt])
	final.Write(tocPage)
	final.Write(out[insertAt:])
	return final.Bytes()
}

// renderTOCPage builds one report page listing every entry as a
// click-to-jump link, styled to match the rest of the report (same
// .page/.inner/.ph/.stag/.stitle shell as every other section).
func renderTOCPage(entries []tocEntry) []byte {
	var b bytes.Buffer
	b.WriteString(`<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">Table of Contents</div>
  </div>
</div>
<div class="stag">Contents</div>
<div class="stitle" role="heading" aria-level="1">Table of Contents</div>
<div class="toc-list">
`)
	for _, e := range entries {
		b.WriteString(`<a class="toc-item" href="#` + e.ID + `"><span class="toc-num">` + e.Number + `</span><span class="toc-title">` + e.Title + `</span></a>` + "\n")
	}
	b.WriteString(`</div>
</div>
</div>
`)
	return b.Bytes()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/reporting/... -run TestInjectTableOfContents -v`
Expected: PASS, all 4 tests. If `TestInjectTableOfContents_InsertsAfterCover` fails on ordering, double check `coverBoundary`'s exact string matches what's used in the test fixture (`<!-- ═══ 1.` — the `═` characters must be typed/pasted exactly, not approximated with `=`).

- [ ] **Step 5: Add the TOC page CSS to `html.go`**

In `orchestrator/internal/reporting/html.go`, insert after line 668 (the `h1{...}` rule) and before line 669 (`h2{...}`):

```css
.toc-list{display:flex;flex-direction:column;margin-top:8px}
.toc-item{display:flex;align-items:baseline;gap:14px;padding:9px 0;
  border-bottom:1px solid var(--line2);text-decoration:none;color:var(--ink)}
.toc-item:hover{color:var(--accent)}
.toc-num{font-size:0.7rem;font-weight:700;color:var(--muted);min-width:28px;flex-shrink:0}
.toc-title{font-size:0.86rem;font-weight:600}
```

This reuses the existing `--line2`, `--ink`, `--accent`, `--muted` custom properties already defined at `html.go:565`'s `:root` block — no new palette introduced.

- [ ] **Step 6: Verify the full package still builds**

Run: `cd orchestrator && go build ./...`
Expected: builds cleanly (this step only adds CSS text inside an existing Go string constant — no Go syntax changes — but confirms no accidental brace/quote mismatch was introduced).

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/reporting/toc.go orchestrator/internal/reporting/toc_test.go orchestrator/internal/reporting/html.go
git commit -m "feat(reporting): TOC extraction/injection engine and its CSS"
```

---

### Task 2: Wire `injectTableOfContents` into `GenerateHTML`

**Files:**
- Modify: `orchestrator/internal/reporting/html.go:1-17` (imports), `html.go:515-532` (`GenerateHTML` body)
- Modify: `orchestrator/internal/reporting/html_test.go` (add one integration test)

**Interfaces:**
- Consumes: `injectTableOfContents(html []byte) []byte` (Task 1).
- Produces: nothing new — `GenerateHTML`'s existing signature and behavior (aside from now including a TOC) are unchanged for all 5 callers.

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/reporting/html_test.go` (same file as the existing `TestGenerateHTMLRendersAllSections` — reuses that test's exact fixture-building pattern, since it's already proven to render successfully):

```go
func TestGenerateHTML_IncludesTableOfContents(t *testing.T) {
	now := time.Date(2026, 6, 9, 10, 30, 0, 0, time.UTC)
	rep := &FullReport{
		GeneratedAt: now,
		Agent: models.Agent{
			AgentID: "agent-123", Hostname: "BANK-WS-01", IPAddress: "10.0.0.5",
			OSVersion: "Windows 11 Pro 23H2", Username: "svc-bas", EnvLabel: "Production",
		},
		Summary: ExecutiveSummary{
			RiskScore: 72, Classification: "High Risk",
			PreventionScore: 41, ExposureScore: 63, CoverageScore: 0,
			KillChainCoverage: 21, KillChainAmplifier: 1.8, Trend: "Baseline",
			TotalRuns: 1, TotalTechniques: 12, PassedTechniques: 5, FailedTechniques: 7,
			LastRunAt: now, LastScenarioName: "RBI Ransomware Resilience Sweep",
			ExposureLevel: "High", DetectionScore: 50, DetectionMeasured: true,
			PenetrationTested: 12, PenetrationFailed: 7, PenetrationPct: 58,
			MTTDMs: 192000,
		},
		ExecutiveConclusion: "This assessment executed 12 techniques against the endpoint, of which 7 were not prevented.",
		TopRiskDrivers: []RiskDriver{
			{TechniqueID: "T1003", Name: "OS Credential Dumping", Tactic: "credential-access",
				Severity: "Critical", Failures: 3, ScorePoints: 30},
		},
		Reliability:   Reliability{Attempted: 12, Valid: 12, Confidence: "High"},
		SkipBreakdown: SkipBreakdown{Policy: 4, Content: 1, Platform: 2},
		Coverage: CoverageSummary{
			ScenarioTotal: 40, Eligible: 26, Executed: 26,
			ScenarioCoveragePct: 65, EligibleCoveragePct: 100,
		},
		Runs: []RunSummary{
			{ID: "run-1", ScenarioName: "RBI Ransomware Resilience Sweep", Status: "completed",
				StartedAt: now, RiskScore: 72, Classification: "High Risk",
				PreventionScore: 41, ExposureScore: 63, TotalTechniques: 12, FailedTechniques: 7},
		},
	}

	var buf bytes.Buffer
	if err := GenerateHTML(&buf, rep, nil); err != nil {
		t.Fatalf("GenerateHTML: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "Table of Contents") {
		t.Fatal("output missing TOC page")
	}
	if !strings.Contains(out, `id="sec-1"`) {
		t.Error("Executive Summary section missing id=\"sec-1\"")
	}
	if !strings.Contains(out, `href="#sec-1"`) {
		t.Error("TOC missing a link to Executive Summary (href=\"#sec-1\")")
	}
	if !strings.Contains(out, "Executive Summary") {
		t.Error("expected Executive Summary section title to still render")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestGenerateHTML_IncludesTableOfContents -v`
Expected: FAIL — at this point `GenerateHTML` doesn't call `injectTableOfContents` yet, so no `id="sec-1"` or "Table of Contents" text will appear in the output.

- [ ] **Step 3: Add the `bytes` import**

In `orchestrator/internal/reporting/html.go`, the import block currently reads:

```go
import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/audspect/bas/internal/reporting/attackdata"
)
```

Add `"bytes"` (alphabetically first):

```go
import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/audspect/bas/internal/reporting/attackdata"
)
```

- [ ] **Step 4: Update `GenerateHTML` to buffer through `injectTableOfContents`**

Replace the current body:

```go
func GenerateHTML(w io.Writer, r *FullReport, compliance []ComplianceSummaryRow) error {
	payload := struct {
		*FullReport
		Compliance []ComplianceSummaryRow `json:"compliance"`
	}{r, compliance}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return err
	}
	_logoLoadOnce.Do(_loadLogos)
	data["logoLightUri"] = _logoLight
	data["logoDarkUri"] = _logoDark
	return reportTmpl.Execute(w, data)
}
```

with:

```go
func GenerateHTML(w io.Writer, r *FullReport, compliance []ComplianceSummaryRow) error {
	payload := struct {
		*FullReport
		Compliance []ComplianceSummaryRow `json:"compliance"`
	}{r, compliance}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return err
	}
	_logoLoadOnce.Do(_loadLogos)
	data["logoLightUri"] = _logoLight
	data["logoDarkUri"] = _logoDark

	var buf bytes.Buffer
	if err := reportTmpl.Execute(&buf, data); err != nil {
		return err
	}
	_, err = w.Write(injectTableOfContents(buf.Bytes()))
	return err
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/reporting/... -v`
Expected: PASS, including the pre-existing `TestGenerateHTMLRendersAllSections` (proves the TOC injection doesn't break normal rendering) and the new `TestGenerateHTML_IncludesTableOfContents`.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/reporting/html.go orchestrator/internal/reporting/html_test.go
git commit -m "feat(reporting): wire table of contents into GenerateHTML"
```

---

### Task 3: Native PDF outline (role="heading" + `GenerateDocumentOutline`)

**Files:**
- Modify: `orchestrator/internal/reporting/html.go` (retrofit `role="heading" aria-level="1"` onto the 21 pre-existing section `.stitle` divs)
- Modify: `orchestrator/internal/reporting/htmlpdf.go:115-154` (extract `printToPDFParams()`, add the outline flag)
- Test: `orchestrator/internal/reporting/htmlpdf_test.go` (add one test)

**Interfaces:**
- Produces: `func printToPDFParams() *page.PrintToPDFParams` — a plain, Chrome-independent function `doRenderPDF` now calls instead of building the params inline.

- [ ] **Step 1: Retrofit `role="heading"` onto the 21 real sections**

In `orchestrator/internal/reporting/html.go`, every one of the 21 pre-existing section headings is the literal, attribute-free string `<div class="stitle">` (confirmed via grep: zero exceptions). Task 1's `renderTOCPage` already writes its own TOC page's `.stitle` div with the role/aria-level attribute baked in from the start (`<div class="stitle" role="heading" aria-level="1">`), so it will **not** match this literal — only the 21 pre-existing occurrences in `reportHTML` will.

Use a single find-and-replace-all across `html.go` (e.g. your editor's "replace all" on the exact literal, or `sed`/equivalent):

- Find: `<div class="stitle">`
- Replace: `<div class="stitle" role="heading" aria-level="1">`

This is a pure accessibility-tree hint (no visual change — CSS targets `.stitle` by class, unaffected by added attributes).

- [ ] **Step 2: Verify the count and that the build still passes**

Run: `cd orchestrator && grep -c 'class="stitle" role="heading"' internal/reporting/html.go`
Expected: `21`

Run: `cd orchestrator && go build ./...`
Expected: builds cleanly (attribute-only HTML text change inside a Go string constant).

- [ ] **Step 3: Write the failing test for `printToPDFParams`**

Append to `orchestrator/internal/reporting/htmlpdf_test.go`:

```go
func TestPrintToPDFParams_GeneratesDocumentOutline(t *testing.T) {
	p := printToPDFParams()
	if !p.GenerateDocumentOutline {
		t.Error("GenerateDocumentOutline = false, want true")
	}
	if !p.PrintBackground {
		t.Error("PrintBackground = false, want true (unchanged from before this refactor)")
	}
	if p.PaperWidth != 8.27 || p.PaperHeight != 11.69 {
		t.Errorf("paper size = %v x %v, want 8.27 x 11.69 (A4, unchanged from before this refactor)", p.PaperWidth, p.PaperHeight)
	}
}
```

- [ ] **Step 4: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestPrintToPDFParams_GeneratesDocumentOutline -v`
Expected: FAIL with "undefined: printToPDFParams"

- [ ] **Step 5: Extract `printToPDFParams` and add the outline flag**

In `orchestrator/internal/reporting/htmlpdf.go`, replace `doRenderPDF`'s inline `page.PrintToPDF()...Do(ctx)` chain:

```go
// doRenderPDF performs a single Chrome CDP print-to-PDF pass.
func doRenderPDF(ctx context.Context, ws string, html []byte) ([]byte, error) {
	allocCtx, cancelAlloc := chromedp.NewRemoteAllocator(ctx, ws)
	defer cancelAlloc()
	taskCtx, cancelTask := chromedp.NewContext(allocCtx)
	defer cancelTask()
	taskCtx, cancelTimeout := context.WithTimeout(taskCtx, 45*time.Second)
	defer cancelTimeout()

	var pdf []byte
	err := chromedp.Run(taskCtx,
		chromedp.Navigate("about:blank"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			ft, err := page.GetFrameTree().Do(ctx)
			if err != nil {
				return err
			}
			return page.SetDocumentContent(ft.Frame.ID, string(html)).Do(ctx)
		}),
		chromedp.Sleep(350*time.Millisecond), // let layout + web fonts settle
		chromedp.ActionFunc(func(ctx context.Context) error {
			buf, _, err := printToPDFParams().Do(ctx)
			if err != nil {
				return err
			}
			pdf = buf
			return nil
		}),
	)
	if err != nil {
		return nil, err
	}
	return pdf, nil
}

// printToPDFParams builds the CDP print-to-PDF request: A4 portrait, zero
// device margins (the report's own CSS owns the page padding and the
// cover's full-bleed band), and a native PDF outline/bookmark sidebar
// generated from the report's role="heading" section titles. Factored out
// of doRenderPDF as a plain function (no Chrome dependency) so the params
// themselves are unit-testable without a live sidecar.
func printToPDFParams() *page.PrintToPDFParams {
	return page.PrintToPDF().
		WithPrintBackground(true).
		WithPaperWidth(8.27).WithPaperHeight(11.69).
		WithMarginTop(0).WithMarginBottom(0).WithMarginLeft(0).WithMarginRight(0).
		WithGenerateDocumentOutline(true)
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/reporting/... -v`
Expected: PASS, including `TestPDFFromReportFallsBackWithoutChrome` (unaffected — it never reaches `doRenderPDF` since `CHROME_WS_URL` is unset in that test) and the new `TestPrintToPDFParams_GeneratesDocumentOutline`.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/reporting/html.go orchestrator/internal/reporting/htmlpdf.go orchestrator/internal/reporting/htmlpdf_test.go
git commit -m "feat(reporting): native PDF outline via role=heading + GenerateDocumentOutline"
```

---

## Self-Review

**Spec coverage:**
- `toc.go`'s `sectionMarker`/`tocEntry`/`injectTableOfContents` → Task 1. ✓
- TOC page markup + CSS matching the report's existing palette → Task 1. ✓
- `GenerateHTML` buffering through `injectTableOfContents` → Task 2. ✓
- `role="heading" aria-level="1"` on all `.stitle` occurrences (21 real sections + the TOC page's own) → Task 1 (TOC page, built already-correct) + Task 3 (retrofit onto the 21 pre-existing). ✓
- `printToPDFParams()` extraction + `GenerateDocumentOutline: true` → Task 3. ✓
- Non-goal: no page numbers → no task adds them. ✓
- Non-goal: `exercise.go` untouched → no task touches it. ✓
- Non-goal: no restructuring of the ~20 sections' conditional logic → Tasks 1-3 never touch a single `{{if}}` in `reportHTML`. ✓
- Testing plan's 4 `toc_test.go` cases, the `GenerateHTML` integration test, and the `printToPDFParams` test → Tasks 1-3, all present with real code, not placeholders. ✓

**Placeholder scan:** no TBD/TODO/dead code — caught and removed a leftover `var _ = strconv.Itoa` artifact from drafting (and the now-unnecessary `"strconv"` import) before finalizing.

**Type consistency:** `injectTableOfContents(html []byte) []byte` (Task 1) called identically in Task 2's `GenerateHTML`. `tocEntry{Number, Title, ID string}` used consistently within Task 1's own `injectTableOfContents`/`renderTOCPage`. `printToPDFParams() *page.PrintToPDFParams` (Task 3) matches `page.PrintToPDF()`'s actual real return type, confirmed by reading `cdproto/page/page.go:863`.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-06-report-toc.md`. Two execution options:

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration
2. **Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?
