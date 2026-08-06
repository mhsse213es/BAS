# Clickable Table of Contents for the BAS Assessment Report — Design Spec

**Goal:** When the BAS Security Assessment Report (`GenerateHTML`, `orchestrator/internal/reporting/html.go`) is viewed in-browser or downloaded as a PDF, it should have a visible, clickable table of contents that jumps to each section, plus a native PDF bookmark/outline sidebar. Scope: the main assessment report only (per-run, campaign, and the audit-pack's `executive-report.pdf`, which all reuse `GenerateHTML`'s output) — the separate Exercise/Purple-Team report (`exercise.go`) is explicitly out of scope for this pass, per the user's own scoping choice.

## Investigation: what already exists

Read the actual template before designing (`html.go`, a single 3406-line `reportHTML` Go template string executed via `reportTmpl.Execute`).

- **Every one of the 21 sections uses an identical, attribute-free marker pattern**, confirmed via grep across the whole file with zero exceptions: `<div class="stag">Section N</div>` immediately followed by `<div class="stitle">Title</div>`. No section has extra attributes on either div.
- **Section numbers include sub-letters** (`Section 10a`, `Section 10b`) and **one number is reused across two mutually exclusive branches**: `Section 11` appears twice — once guarded by `{{if .variantCoverage}}{{if .variantCoverage.hasData}}` ("Variant Coverage Analysis", per-run) and once by `{{if .campaignVariantCoverage}}{{if .campaignVariantCoverage.hasData}}` ("Variant Coverage Trends", campaign). These are different data fields populated by different report-generation paths (per-run vs. campaign) — verified by reading both branches' surrounding conditionals — so only one "Section 11" is ever present in a single rendered document. No id collision risk.
- **The cover page ends cleanly** at `html.go:973-974` (`</div>\n</div>` closing `.cover` and its outer `.page`), immediately followed by a `<!-- ═══ 1. EXECUTIVE SUMMARY ═... -->` comment and the first content `<div class="page">` at line 975-976. This is the exact insertion point for a new TOC page.
- **`GenerateHTML` currently streams straight to its `io.Writer` argument**: `return reportTmpl.Execute(w, data)` (`html.go:531`). Its 5 callers were checked: 3 pass an `http.ResponseWriter` directly (`campaign_handlers.go:275`, `handlers.go:3798,4437` — plain full-page HTML responses, no chunked/streaming requirement), 2 already pass a `*bytes.Buffer` (`auditpack.go:96`, `htmlpdf.go:28`). None depend on incremental/streamed output, so switching `GenerateHTML` to render into an internal buffer first is transparent and safe for every caller — no signature change needed.
- **PDF generation** (`htmlpdf.go`) takes `GenerateHTML`'s output and prints it via Chrome DevTools Protocol's `page.PrintToPDF()` (`chromedp/cdproto` `v0.0.0-20260321001828-e3e3800016bc`). That package's `PrintToPDFParams` already exposes `WithGenerateDocumentOutline(bool)` — "Whether or not to embed the document outline into the PDF" (confirmed by reading `cdproto/page/page.go:855,987-989`) — a native, one-line way to populate a PDF reader's bookmark sidebar from the document's heading structure. Not currently used (`htmlpdf.go:138-142`'s builder chain only sets background/paper-size/margins).
- **`GenerateDocumentOutline` needs actual heading structure to find**, and the report's `.stitle` divs are plain `<div>`s, not semantic `<h1>`-`<h6>` tags — Chrome's outline builder reads the accessibility tree's heading role, which styled `<div>`s don't get automatically. Confirmed this is fixable additively: adding `role="heading" aria-level="1"` to an element makes assistive-tech/accessibility-tree tooling treat it as a heading without any visual or layout change.
- **`auditpack.go`** (`orchestrator/internal/reporting/auditpack.go:92-116`) reuses `GenerateHTML`'s buffered output for both the audit pack's HTML entry and its Chrome-rendered `executive-report.pdf` — confirming the audit-pack path gets the TOC automatically once `GenerateHTML` itself has it, no separate change needed there.

## Architecture

### 1. New file: `orchestrator/internal/reporting/toc.go`

```go
package reporting

import "regexp"

// sectionMarker matches one section's stag/stitle pair in fully-rendered
// report HTML -- after every {{if}} in reportHTML has already resolved, so
// this only ever sees sections that actually appear in this specific
// report. Confirmed via grep: no section in reportHTML deviates from this
// exact, attribute-free shape.
var sectionMarker = regexp.MustCompile(`<div class="stag">Section ([^<]+)</div>\s*<div class="stitle">([^<]+)</div>`)

// tocEntry is one row of the extracted table of contents.
type tocEntry struct {
	Number string // e.g. "1", "10a", "11" -- raw text between the stag tags
	Title  string // raw HTML text between the stitle tags, e.g. may contain "&amp;"
	ID     string // anchor id, e.g. "sec-10a"
}

// injectTableOfContents scans rendered report HTML for section markers,
// stamps an id onto each one, and inserts a new table-of-contents page
// (styled to match the rest of the report) immediately after the cover
// page. Returns html unchanged if no sections are found (defensive --
// should not happen given reportHTML's structure, but GenerateHTML must
// never fail or produce broken output because of this).
func injectTableOfContents(html []byte) []byte
```

`tocEntry.ID` is `"sec-" + strings.ToLower(strings.TrimSpace(Number))` (e.g. `sec-10a`, `sec-11`) — safe as an HTML `id` since section numbers are always short alphanumeric tokens (verified: `1` through `21`, plus `10a`/`10b`).

**Algorithm:**
1. Run `sectionMarker.FindAllSubmatchIndex(html, -1)` to get every match's byte offsets (not just the matched text) — needed because step 2 rewrites the matched region in place.
2. Build the `[]tocEntry` list in document order from the submatches.
3. If the list is empty, return `html` unchanged (defensive fallback).
4. Rewrite `html`, inserting `id="sec-{ID}"` into each matched `<div class="stag">` opening tag (`<div class="stag" id="sec-10a">Section 10a</div>`) — done via a single pass building a new `[]byte` from the original interspersed with the modified matches, using the indices from step 1 (avoids re-matching against already-modified text, which a naive `ReplaceAll` loop would risk if two sections' raw text ever overlapped a pattern — they don't here, but building from indices is the robust way regardless).
5. Render the TOC page (see below) from the `[]tocEntry` list.
6. Find the byte offset of the cover page's closing marker — the literal string `"\n\n<!-- ═══ 1."` (matches `html.go`'s existing comment convention, confirmed present verbatim before every report's first section) — and insert the TOC page HTML immediately before it. If that marker isn't found (defensive), insert the TOC page immediately before the first section match's start offset instead, which is always known once step 1 has run.

### 2. TOC page markup

A new page matching the existing section shell exactly (same `.page`/`.inner`/`.ph` header, same `.stag`/`.stitle` classes so it's visually indistinguishable from a real section), body content a simple linked list:

```html
<div class="page">
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
  <a class="toc-item" href="#sec-1"><span class="toc-num">1</span><span class="toc-title">Executive Summary</span></a>
  <!-- ...one per tocEntry, in document order... -->
</div>
</div>
</div>
```

New CSS added to `reportHTML`'s existing `<style>` block (alongside the other section styles already there, e.g. `.stag`/`.stitle`'s own rules): `.toc-list` a simple vertical flex list, `.toc-item` a flex row (number + title, `text-decoration:none`, `color:inherit`, a bottom border between rows) — matching the report's existing navy/teal palette (`--navy`, `--accent`, `--muted` custom properties already defined at `html.go:565`), not introducing a new visual language.

### 3. `GenerateHTML` change (`html.go:515-532`)

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

`bytes` is already imported in `html.go` (used elsewhere in the file); no new imports needed there.

### 4. Native PDF outline

Two small, independent additions:

- **`html.go`**: add `role="heading" aria-level="1"` to the static `.stitle` div markup used by every section (a literal string edit to the `reportHTML` template — `.stitle` appears identically in all 21 sections, so this is one attribute addition applied to each occurrence) and to the new TOC page's own `.stitle` above. Zero visual change — CSS styling is entirely class-driven, unaffected by ARIA attributes.
- **`htmlpdf.go:138-142`**: add `.WithGenerateDocumentOutline(true)` to the existing `page.PrintToPDF()` builder chain in `doRenderPDF`. That chain is currently built and executed (`.Do(ctx)`) inline inside `doRenderPDF`, which isn't unit-testable without a live Chrome sidecar (confirmed: `htmlpdf_test.go`'s only existing test, `TestPDFFromReportFallsBackWithoutChrome`, exercises the no-sidecar-configured fallback path, not the CDP call itself — there is no existing pattern for asserting on `PrintToPDFParams` to follow). Extract the params construction into a small pure function so the outline flag is verifiable without Chrome:
  ```go
  func printToPDFParams() *page.PrintToPDFParams {
  	return page.PrintToPDF().
  		WithPrintBackground(true).
  		WithPaperWidth(8.27).WithPaperHeight(11.69).
  		WithMarginTop(0).WithMarginBottom(0).WithMarginLeft(0).WithMarginRight(0).
  		WithGenerateDocumentOutline(true)
  }
  ```
  `doRenderPDF` then calls `printToPDFParams().Do(ctx)` in place of the inline chain — behavior-identical, just factored so the params themselves are a plain value a test can inspect.

These two are independent of the in-document TOC page (different mechanism — PDF-reader-native sidebar vs. visible document content) and degrade gracefully on their own: a PDF reader that ignores the outline just doesn't show a sidebar; the in-document TOC page still works regardless.

## Non-goals

- **No page numbers in the TOC entries.** The exact PDF page a section lands on isn't knowable at HTML-generation time (Chrome's print pagination depends on dynamic content flow/font metrics resolved at render time, not before). Entries are click-to-jump links only, matching what "clickable index" asks for.
- **No changes to `exercise.go`** — explicitly out of scope per the user's own scoping choice, despite sharing the same `.stag`/`.stitle` convention (revisit later if wanted; the same `injectTableOfContents` helper could be reused as-is against `ExerciseReportHTML`'s output).
- **No restructuring of the 3406-line template's section logic** (rejected Approach B) — the TOC is built entirely from the template's already-correct rendered output, not by duplicating its ~20 sections' worth of conditional logic in Go.

## Testing

- `orchestrator/internal/reporting/toc_test.go` (new):
  - `TestInjectTableOfContents_ExtractsSectionsInOrder`: a small fixture HTML string with 3 stag/stitle pairs (including one with an HTML entity in the title, e.g. `MITRE ATT&amp;CK`) asserts the returned HTML contains 3 `id="sec-N"` stamps in the original document order and a TOC page with matching `href="#sec-N"` links, entity preserved verbatim (not double-escaped).
  - `TestInjectTableOfContents_SubLetterSections`: fixture with `Section 10a`/`Section 10b` asserts ids `sec-10a`/`sec-10b`.
  - `TestInjectTableOfContents_NoSections_ReturnsUnchanged`: fixture HTML with no stag/stitle pairs at all asserts the output is byte-identical to the input.
  - `TestInjectTableOfContents_InsertsAfterCover`: fixture mimicking the real cover-to-first-section boundary (the literal `<!-- ═══ 1.` comment) asserts the TOC page appears between the cover content and that comment.
  - `TestGenerateHTML_IncludesTableOfContents`: existing test pattern in `html.go`'s own test file — render a real, minimal `FullReport` through `GenerateHTML` and assert the output contains a `.toc-list` with at least one entry, and that at least one real section (e.g. "Executive Summary") has a matching `id="sec-1"`.
  - `htmlpdf_test.go` (existing file): `TestPrintToPDFParams_GeneratesDocumentOutline` — calls the new `printToPDFParams()` directly (no Chrome dependency, since it no longer executes `.Do(ctx)`) and asserts `.GenerateDocumentOutline == true`, alongside the existing paper-size/margin values to guard against a future edit accidentally dropping them while adding something else.
