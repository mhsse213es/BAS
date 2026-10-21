package lab

// Injection-pattern classification for access events. The classifier returns class names only (see
// detect.Signature*). The matched text is never kept, so a request body is never stored through an event.

import (
	"net/url"
	"regexp"
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
	if cookieAttribute.MatchString(text) {
		out = append(out, detect.SignatureCookie)
	}
	if prototypeKey.MatchString(text) {
		out = append(out, detect.SignaturePrototype)
	}
	return out
}

// cookieAttribute matches a cookie attribute injected after a semicolon: a named attribute with a value (Domain=, Path=,
// Expires=, Max-Age=, SameSite=) or a flag (HttpOnly, Secure). A semicolon followed by ordinary words does not match.
var cookieAttribute = regexp.MustCompile(`(?i);\s*(?:domain|path|expires|max-age|samesite)\s*=|(?i);\s*(?:httponly|secure)\b`)

// prototypeKey matches a prototype key in key position: "__proto__": (a JSON key), a __proto__ path segment, or
// constructor.prototype. The same word as a string value, or the word "prototype" on its own, does not match.
var prototypeKey = regexp.MustCompile(`"__proto__"\s*:|__proto__\.|constructor\s*\.\s*prototype`)
