package taxii

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/audspect/bas/internal/iocregistry"
)

// stixEnvelope is a minimal, deliberately partial STIX 2.1 SDO shape --
// enough to route and parse an `indicator`, without a full STIX type
// hierarchy Phase 1 doesn't need (YAGNI: Phase 2/3 add more fields/types
// when they route threat-actor/campaign/malware/tool SDOs).
type stixEnvelope struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Modified    string `json:"modified"`
	Pattern     string `json:"pattern"`
	PatternType string `json:"pattern_type"`
}

// ParseObject unmarshals one raw SDO into its typed envelope. Returns an
// error only for invalid JSON or a missing id/type -- an unrecognized
// `type` or `pattern_type` value is a valid parse result the caller
// (Task 6's Normalizer) routes as "skipped", never a parse error.
func ParseObject(raw json.RawMessage) (stixEnvelope, error) {
	var env stixEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return stixEnvelope{}, fmt.Errorf("unmarshal STIX object: %w", err)
	}
	if env.ID == "" || env.Type == "" {
		return stixEnvelope{}, fmt.Errorf("STIX object missing id/type")
	}
	return env, nil
}

// simplePatternRE matches exactly one bracketed single-comparison STIX
// pattern, e.g. "[ipv4-addr:value = '203.0.113.9']". Composite/boolean
// patterns (AND/OR, multiple bracket groups) never match this regex and
// so are never partially parsed.
var simplePatternRE = regexp.MustCompile(`^\[([a-zA-Z0-9\-]+):([a-zA-Z0-9_.'"-]+)\s*=\s*'([^']*)'\]$`)

// ParsePattern extracts (Type, value) from a single-comparison STIX
// pattern. ok=false for composite/boolean patterns or unrecognized
// observable paths -- the caller treats that as "skipped", never a
// partial match. Covers exactly the observable/property combinations
// named in the Phase 1 spec: ipv4-addr/ipv6-addr:value, domain-name:value,
// url:value, file:hashes.'SHA-256'|'MD5'|'SHA-1'.
func ParsePattern(pattern string) (t iocregistry.Type, value string, ok bool) {
	m := simplePatternRE.FindStringSubmatch(pattern)
	if m == nil {
		return "", "", false
	}
	object, path, val := m[1], m[2], m[3]
	switch {
	case object == "ipv4-addr" && path == "value":
		return iocregistry.TypeIP, val, true
	case object == "ipv6-addr" && path == "value":
		return iocregistry.TypeIP, val, true
	case object == "domain-name" && path == "value":
		return iocregistry.TypeDomain, val, true
	case object == "url" && path == "value":
		return iocregistry.TypeURL, val, true
	case object == "file" && (path == "hashes.'SHA-256'" || path == "hashes.'MD5'" || path == "hashes.'SHA-1'"):
		return iocregistry.TypeFileHash, val, true
	default:
		return "", "", false
	}
}
