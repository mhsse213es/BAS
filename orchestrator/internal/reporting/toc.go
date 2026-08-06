package reporting

import (
	"bytes"
	"regexp"
	"strings"
)

// sectionMarker matches one section's stag/stitle pair in fully-rendered
// report HTML -- after every {{if}} in reportHTML has already resolved, so
// this only ever sees sections that actually appear in this specific
// report. The [^>]* tolerates the role="heading" aria-level="1" attributes
// reportHTML's .stitle divs carry (added for native PDF outline support --
// see printToPDFParams), and any other attributes either div gains later.
var sectionMarker = regexp.MustCompile(`<div class="stag"[^>]*>Section ([^<]+)</div>\s*<div class="stitle"[^>]*>([^<]+)</div>`)

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
		// matches[0][0] is an offset into the ORIGINAL html, but everything
		// before the first match is untouched by the rewrite above (the
		// rewrite only starts diverging at matches[0][0] itself), so that
		// same offset is valid in out too -- no need to re-match against the
		// now-modified (id/role-attribute-bearing) text, which wouldn't match
		// sectionMarker's attribute-free pattern anymore anyway.
		insertAt = matches[0][0]
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
