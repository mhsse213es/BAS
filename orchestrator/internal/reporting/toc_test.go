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
