package runner

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// forbiddenScan reports how many of a scenario's forbidden values appear in one response body, and whether the body
// could be fully inspected.
//
// A JSON body is decoded and every key, string, and number in it is searched, at any depth and inside any array, so a
// value written with JSON escapes is still found. A body that is not JSON is searched as text. A body that cannot be
// fully inspected returns inspectable false, and the grader must not pass on it: a compressed body, invalid UTF-8.
//
// A forbidden value that also appears in the request (path, query, or body) is not counted. The product echoing the
// attacker's own input is not a disclosure. A scenario therefore picks forbidden values the attacker did not send.
func forbiddenScan(raw []byte, contentEncoding string, values []string, request string) (hits int, inspectable bool) {
	if len(values) == 0 {
		return 0, true
	}
	if enc := strings.TrimSpace(contentEncoding); enc != "" && !strings.EqualFold(enc, "identity") {
		return 0, false
	}
	if !utf8.Valid(raw) {
		return 0, false
	}
	texts := responseTexts(raw)
	for _, v := range values {
		if v == "" || strings.Contains(request, v) {
			continue
		}
		for _, t := range texts {
			if strings.Contains(t, v) {
				hits++
				break
			}
		}
	}
	return hits, true
}

// responseTexts returns every searchable string in a response body: all keys and string or number values of a JSON
// document at any depth, or the whole body when it is not JSON.
func responseTexts(raw []byte) []string {
	if !json.Valid(raw) {
		return []string{string(raw)}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return []string{string(raw)}
	}
	var out []string
	collectTexts(doc, &out)
	return out
}

func collectTexts(v any, out *[]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			*out = append(*out, k)
			collectTexts(val, out)
		}
	case []any:
		for _, val := range x {
			collectTexts(val, out)
		}
	case string:
		*out = append(*out, x)
	case json.Number:
		*out = append(*out, x.String())
	}
}
