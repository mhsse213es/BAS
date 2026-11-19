// Package scope decides whether an HTTP request path lies inside a target's registered path scope. The runner, the job service
// and the result validator all use it, so one rule governs submission, execution and the recorded evidence.
package scope

import (
	"net/url"
	"strings"
)

// Normalise returns the path's segments with the query and fragment removed. ok is false for any path that cannot be matched
// safely: not rooted at "/", containing a backslash or NUL, an empty or dot segment, or an encoded form that decodes to one.
func Normalise(p string) (segments []string, ok bool) {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\\x00") {
		return nil, false
	}
	rest := strings.TrimPrefix(p, "/")
	if rest == "" {
		return []string{}, true
	}
	rest = strings.TrimSuffix(rest, "/")
	for seg := range strings.SplitSeq(rest, "/") {
		decoded, err := url.PathUnescape(seg)
		if err != nil || seg == "" || seg == "." || seg == ".." || decoded == "." || decoded == ".." || strings.ContainsAny(decoded, "/\\\x00") {
			return nil, false
		}
		segments = append(segments, seg)
	}
	return segments, true
}

// Allowed reports whether p is covered by one of the allowed path prefixes. A prefix covers itself and every path below it,
// compared by whole segments: "/api/orders" covers "/api/orders/ORD-1" but not "/api/orders-admin". An empty list allows nothing.
func Allowed(allowed []string, p string) bool {
	segs, ok := Normalise(p)
	if !ok {
		return false
	}
	for _, a := range allowed {
		prefix, ok := Normalise(a)
		if !ok || len(prefix) > len(segs) {
			continue
		}
		match := true
		for i := range prefix {
			if prefix[i] != segs[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// ValidPrefix reports whether s is acceptable as a registered allowed path: rooted, normalisable, no query or fragment, and not
// the bare root (which would allow every path).
func ValidPrefix(s string) bool {
	if strings.ContainsAny(s, "?#") {
		return false
	}
	segs, ok := Normalise(s)
	return ok && len(segs) > 0
}

// StaticPrefix returns the part of a step path template before its first "{" placeholder, with the query removed and any
// trailing slash dropped. "/api/orders/{object}" gives "/api/orders". A template that begins with a placeholder gives "".
func StaticPrefix(template string) string {
	if i := strings.IndexAny(template, "?#"); i >= 0 {
		template = template[:i]
	}
	if i := strings.Index(template, "{"); i >= 0 {
		template = template[:i]
	}
	if len(template) > 1 {
		template = strings.TrimSuffix(template, "/")
	}
	return template
}
