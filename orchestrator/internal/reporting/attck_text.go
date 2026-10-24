package reporting

import (
	"regexp"
	"strings"
)

var (
	attckMDLinkRe  = regexp.MustCompile(`\[([^\]]+)\]\([^)]*\)`)
	attckCiteRe    = regexp.MustCompile(`\s*\(Citation:[^)]*\)`)
	attckHTMLTagRe = regexp.MustCompile(`</?[a-zA-Z][^>]*>`)
	attckSpaceRe   = regexp.MustCompile(`\s+`)
)

// cleanATTCKText turns ATT&CK enrichment prose into plain text for the report.
// The source data carries Markdown links, Wikipedia-style citation markers and
// occasional HTML tags; none of that renders meaningfully in a printed report.
func cleanATTCKText(s string) string {
	s = attckMDLinkRe.ReplaceAllString(s, "$1")
	s = attckCiteRe.ReplaceAllString(s, "")
	s = attckHTMLTagRe.ReplaceAllString(s, "")
	s = attckSpaceRe.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}
