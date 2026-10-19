package dlpreport

// PreventionStats aggregates enforcement outcomes for one group. Unknown
// results stay in Total so they lower Rate rather than disappearing.
type PreventionStats struct {
	Total      int
	Prevented  int
	Allowed    int
	Overridden int
	Challenged int
	Unknown    int
	// Measurable counts records whose enforcement is not Unknown. A group
	// with Measurable == 0 has no evidence either way.
	Measurable int
	Rate       float64
}

// PreventionByGroup buckets records by key and computes each group's
// prevention statistics. Prevented is Blocked, Quarantined or Encrypted only.
func PreventionByGroup(records []Record, key func(Record) string) map[string]PreventionStats {
	out := make(map[string]PreventionStats)
	for _, r := range records {
		g := key(r)
		s := out[g]
		s.Total++
		switch classifyEnforcement(r.Enforcement) {
		case enforcementPrevented:
			s.Prevented++
			s.Measurable++
		case enforcementAllowed:
			s.Allowed++
			s.Measurable++
		case enforcementOverridden:
			s.Overridden++
			s.Measurable++
		case enforcementChallenged:
			s.Challenged++
			s.Measurable++
		default:
			s.Unknown++
		}
		out[g] = s
	}
	for g, s := range out {
		if s.Total > 0 {
			s.Rate = float64(s.Prevented) / float64(s.Total)
		}
		out[g] = s
	}
	return out
}

type enforcementBucket int

const (
	enforcementUnknown enforcementBucket = iota
	enforcementPrevented
	enforcementAllowed
	enforcementOverridden
	enforcementChallenged
)

func classifyEnforcement(e EnforcementOutcome) enforcementBucket {
	switch e {
	case EnforcementBlocked, EnforcementQuarantined, EnforcementEncrypted:
		return enforcementPrevented
	case EnforcementAllowed:
		return enforcementAllowed
	case EnforcementOverridden:
		return enforcementOverridden
	case EnforcementChallenged:
		return enforcementChallenged
	default:
		return enforcementUnknown
	}
}
