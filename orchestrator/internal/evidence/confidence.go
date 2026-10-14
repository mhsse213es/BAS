package evidence

// confidenceMappingVersion versions the per-source normalization table
// (spec §7.3). Bump it, and add a new table/branch, rather than mutating
// values an already-generated content_generations.evidence_snapshot_hash
// depends on.
const confidenceMappingVersion = "tcf2b-confidence-v1"

// mispConfidenceLevels is MISP's confidence-level taxonomy, closed and
// documented (spec §7.3) — an unrecognized raw string normalizes to nil,
// never an invented value.
var mispConfidenceLevels = map[string]int{
	"low":      25,
	"medium":   55,
	"high":     85,
	"complete": 100,
}

func ptrStr(s string) *string { return &s }
func ptrInt(i int) *int       { return &i }

// NormalizeConfidence maps one source's raw confidence string to a 0-100
// normalized value, per the closed, versioned, per-source table in spec
// §7.3. raw is preserved verbatim when non-empty and the source structurally
// carries confidence at all; bundle and OTX never do, so both return (nil,
// nil, version) regardless of input — no invented 100, ever.
func NormalizeConfidence(source, raw string) (rawOut *string, normalized *int, mappingVersion string) {
	mappingVersion = confidenceMappingVersion
	switch source {
	case "opencti":
		if raw == "" {
			return nil, nil, mappingVersion
		}
		var n int
		for _, c := range raw {
			if c < '0' || c > '9' {
				return ptrStr(raw), nil, mappingVersion
			}
			n = n*10 + int(c-'0')
		}
		return ptrStr(raw), ptrInt(n), mappingVersion
	case "misp":
		if raw == "" {
			return nil, nil, mappingVersion
		}
		if n, ok := mispConfidenceLevels[raw]; ok {
			return ptrStr(raw), ptrInt(n), mappingVersion
		}
		return ptrStr(raw), nil, mappingVersion
	default: // "bundle", "otx": no structural confidence (spec §7.3)
		return nil, nil, mappingVersion
	}
}
