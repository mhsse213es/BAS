package reporting

import "strings"

// reportDesignCSS returns the stylesheet of the main BAS report: the page,
// cover, table, card, print and footer rules that define how every PDF looks.
// Every PDF (run, campaign, sweep, exercise, compliance, AD assessment, board)
// includes it, so they all share one design.
func reportDesignCSS() string {
	a := strings.Index(reportHTML, "<style>")
	if a < 0 {
		return ""
	}
	b := strings.Index(reportHTML[a:], "</style>")
	if b < 0 {
		return ""
	}
	return reportHTML[a+len("<style>") : a+b]
}
