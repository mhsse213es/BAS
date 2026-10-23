package model

import (
	"fmt"
	"strings"
)

// A signature identifies an operation by what it does on the wire, not by the name the document gives
// it: "METHOD /normalised/path-template". The method is upper case; every whole-segment {param} becomes
// {} (so /payments/{id} and /payments/{paymentId} are the same signature); a trailing slash is dropped;
// there is no query. Authorisation decisions (the engagement's classes and operation list) are keyed by
// signature because an operationId comes from the document under test and is not trustworthy.

// Signature returns the canonical signature of a method and path template, or an error for an empty,
// relative or odd path (empty segment, "." or "..", query or fragment, whitespace, partial or nested
// braces).
func Signature(method, path string) (string, error) {
	if method == "" {
		return "", fmt.Errorf("signature: method is empty")
	}
	for _, r := range method {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return "", fmt.Errorf("signature: method %q is not valid", method)
		}
	}
	if !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("signature: path %q must start with /", path)
	}
	if strings.ContainsAny(path, "?#") {
		return "", fmt.Errorf("signature: path %q has a query or fragment", path)
	}
	for _, r := range path {
		if r <= ' ' || r == 0x7f {
			return "", fmt.Errorf("signature: path %q has whitespace or control characters", path)
		}
	}
	norm := "/"
	if path != "/" {
		trimmed := strings.TrimSuffix(path, "/")
		segs := strings.Split(trimmed[1:], "/")
		for i, seg := range segs {
			switch {
			case seg == "" || seg == "." || seg == "..":
				return "", fmt.Errorf("signature: path %q has an empty or relative segment", path)
			case strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}"):
				name := seg[1 : len(seg)-1]
				if strings.ContainsAny(name, "{}") {
					return "", fmt.Errorf("signature: path %q has a malformed parameter segment", path)
				}
				segs[i] = "{}"
			case strings.ContainsAny(seg, "{}"):
				return "", fmt.Errorf("signature: path %q has a partial parameter segment %q", path, seg)
			}
		}
		norm = "/" + strings.Join(segs, "/")
	}
	return strings.ToUpper(method) + " " + norm, nil
}

// ParseSignature canonicalises text of the form "METHOD /path" (one space). An operation id or any
// other text is an error.
func ParseSignature(s string) (string, error) {
	i := strings.IndexByte(s, ' ')
	if i <= 0 || strings.Contains(s[i+1:], " ") {
		return "", fmt.Errorf("%q is not a signature of the form \"METHOD /path\"", s)
	}
	return Signature(s[:i], s[i+1:])
}

// Signature returns the operation's signature, or "" when its method or path is not valid (the
// importer never produces such an operation).
func (o Operation) Signature() string {
	s, err := Signature(o.Method, o.Path)
	if err != nil {
		return ""
	}
	return s
}
