package search

import "strings"

// ParsedQuery is the result of parsing a raw search-box string into free
// text plus recognized operator filters. Returning a struct (not multiple
// return values) means adding new operator fields later (Status, OS, Tag,
// once those columns exist) never changes any caller's call site. See
// design doc §Architecture 1.
type ParsedQuery struct {
	FreeText string
	DocType  string // "" if no valid type: filter was applied

	// InvalidFilters holds every field:value token that couldn't be
	// applied -- an unsupported field name, an unrecognized value for a
	// supported field, or a field that appeared more than once. Search
	// behaves exactly as if these tokens were never typed; this is kept
	// only so a future UI can surface "unknown filter" hints without
	// touching the parser.
	InvalidFilters []InvalidFilter
}

type InvalidFilter struct {
	Name  string
	Value string
}

// SupportedOperators lists every field name ParseQuery currently validates
// and applies -- the single source of truth shared by validation here and
// the GET /api/search/operators advertisement endpoint, so they can never
// drift from each other.
var SupportedOperators = []string{"type"}

// knownDocTypes are the only values a type: filter can resolve to --
// matches the 12 doc_types ReindexAll builds (internal/search/store.go).
var knownDocTypes = map[string]bool{
	"scenario": true, "run": true, "finding": true, "actor": true,
	"campaign": true, "malware": true, "tool": true, "technique": true,
	"rule": true, "compliance_control": true, "detection_connector": true, "action_connector": true,
}

// ParseQuery splits raw on whitespace, treats any token shaped like
// field:value as an operator, and validates only the fields in
// SupportedOperators -- everything else (an unsupported field, a bad
// value, or a duplicated field) is rejected and recorded in
// InvalidFilters rather than applied. See design doc §Architecture 1.
func ParseQuery(raw string) ParsedQuery {
	fields := map[string][]string{} // field -> every value seen, in order
	var freeTextParts []string

	for _, tok := range strings.Fields(raw) {
		field, value, ok := splitOperatorToken(tok)
		if !ok {
			freeTextParts = append(freeTextParts, tok)
			continue
		}
		fields[field] = append(fields[field], value)
	}

	pq := ParsedQuery{FreeText: strings.Join(freeTextParts, " ")}
	for field, values := range fields {
		if len(values) > 1 {
			pq.InvalidFilters = append(pq.InvalidFilters, InvalidFilter{
				Name: field, Value: "duplicate: " + strings.Join(values, ", "),
			})
			continue
		}
		value := values[0]
		if !isSupportedOperator(field) {
			pq.InvalidFilters = append(pq.InvalidFilters, InvalidFilter{Name: field, Value: value})
			continue
		}
		// field == "type" is the only supported operator today. None of
		// the 8 known doc_type values end in "s", so a single trailing-s
		// strip correctly normalizes both "scenarios" and "scenario".
		normalized := strings.TrimSuffix(strings.ToLower(value), "s")
		if knownDocTypes[normalized] {
			pq.DocType = normalized
		} else {
			pq.InvalidFilters = append(pq.InvalidFilters, InvalidFilter{Name: "type", Value: value})
		}
	}
	return pq
}

// splitOperatorToken reports whether tok looks like field:value -- a
// leading run of letters/digits/underscore/hyphen, a colon, then one or
// more non-whitespace characters. strings.Fields already guarantees tok
// has no internal whitespace, so this only needs to find the first colon
// and validate the field portion.
func splitOperatorToken(tok string) (field, value string, ok bool) {
	i := strings.IndexByte(tok, ':')
	if i <= 0 || i == len(tok)-1 {
		return "", "", false
	}
	for _, r := range tok[:i] {
		if !isFieldChar(r) {
			return "", "", false
		}
	}
	return strings.ToLower(tok[:i]), tok[i+1:], true
}

func isFieldChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-'
}

func isSupportedOperator(field string) bool {
	for _, f := range SupportedOperators {
		if f == field {
			return true
		}
	}
	return false
}
