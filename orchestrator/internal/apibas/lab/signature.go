package lab

// Injection-pattern classification for access events. The classifier returns class names only (see
// detect.Signature*). The matched text is never kept, so a request body is never stored through an event.

import (
	"net/url"
	"strings"

	"github.com/audspect/bas/internal/apibas/detect"
)

// requestTargetText is the request target as a detector reads it: the path, and every query value
// decoded, so an encoded traversal or quote is seen as the characters it encodes.
func requestTargetText(path string, q url.Values) string {
	parts := []string{path}
	for _, vals := range q {
		parts = append(parts, vals...)
	}
	return strings.Join(parts, "\n")
}

// injectionClasses returns the injection-pattern classes present in a text, in a fixed order.
func injectionClasses(text string) []string {
	var out []string
	if tautology(text) {
		out = append(out, detect.SignatureSQL)
	}
	if strings.Contains(text, "../") || strings.Contains(text, `..\`) {
		out = append(out, detect.SignatureTraverse)
	}
	if strings.Contains(text, "*)(") || strings.Contains(text, ")(") {
		out = append(out, detect.SignatureLDAP)
	}
	if strings.Contains(text, "{{") || strings.Contains(text, "${") {
		out = append(out, detect.SignatureTemplate)
	}
	return out
}
