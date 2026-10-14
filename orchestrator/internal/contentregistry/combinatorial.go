package contentregistry

import (
	"fmt"
	"sort"

	"github.com/audspect/bas/internal/reporting/attackdata"
)

const (
	combinatorialClassifier        = "combinatorial"
	combinatorialClassifierVersion = "1"
)

// tacticPairRisk names one unordered pair of MITRE ATT&CK tactics whose
// combination within a single composed candidate is an elevated real-world
// risk -- not because the combination looks like a realistic attack (that
// is this product's purpose), but because one tactic's presence removes a
// safety net the other tactic's individually-safe step rating assumed
// (spec §2.1).
type tacticPairRisk struct {
	tacticA string
	tacticB string
	reason  string
}

// combinationRiskCatalog is a hardcoded, code-reviewed value -- never a
// database table, never editable at runtime (spec §2.3, acceptance
// criterion 6). Starter set only; see spec §4 for explicitly-deferred
// candidates.
var combinationRiskCatalog = []tacticPairRisk{
	{
		tacticA: "defense-evasion", tacticB: "persistence",
		reason: "disabling defenses then persisting removes the observability this persistence mechanism's reversibility assumed",
	},
	{
		tacticA: "defense-evasion", tacticB: "execution",
		reason: "disabling defenses then executing removes the observability this execution step's reversibility assumed",
	},
}

// combinatorialRisk resolves each component's ATT&CK tactic(s) via
// attackdata.Lookup, unions them, and checks the union against
// combinationRiskCatalog (spec §2.2-§2.3). An unresolvable technique_id
// fails closed: the whole composition is refused, even if no catalog pair
// would otherwise apply (spec acceptance criterion 3). On success, returns
// the sorted resolved tactic union for the caller to record.
func combinatorialRisk(components []loadedComponent) ([]string, error) {
	tacticSet := map[string]bool{}
	for _, c := range components {
		e := attackdata.Lookup(c.techniqueID)
		if e == nil {
			return nil, fmt.Errorf("composition refused: technique %s has no known ATT&CK tactic, cannot be safety-assessed", c.techniqueID)
		}
		for _, t := range e.Tactics {
			tacticSet[t] = true
		}
	}
	for _, rule := range combinationRiskCatalog {
		if tacticSet[rule.tacticA] && tacticSet[rule.tacticB] {
			return nil, fmt.Errorf("composition refused: combining %s and %s tactics is an elevated-risk combination (%s)",
				rule.tacticA, rule.tacticB, rule.reason)
		}
	}
	tactics := make([]string, 0, len(tacticSet))
	for t := range tacticSet {
		tactics = append(tactics, t)
	}
	sort.Strings(tactics)
	return tactics, nil
}
