package contentregistry

import (
	"fmt"
	"sort"

	"github.com/audspect/bas/internal/reporting/attackdata"
)

const (
	combinatorialClassifier = "combinatorial"
	// v2 added the defense-evasion + exfiltration and defense-evasion +
	// lateral-movement pairs (see combinationRiskCatalog). Bumped so a
	// content_safety_verdicts PASS row records which rule set it was checked
	// against -- a v1 PASS did not see these pairs.
	combinatorialClassifierVersion = "2"
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
	// v2 additions (spec §4 deferred candidates, promoted once the mechanism
	// was proven). Both pairs have near-zero single-technique tactic
	// co-occurrence in the embedded ATT&CK dataset (exfiltration: 0 techniques
	// carry defense-evasion too; lateral-movement: only the T1550 family, which
	// genuinely is both tactics), so they fire on a real two-part combination
	// rather than over-refusing a single dual-tagged technique. The
	// defense-evasion + persistence/privilege-escalation combination was
	// deliberately NOT added here: 78 single techniques carry both of those,
	// so a presence-based rule (this check unions tactics, it is not
	// component-attributed) would refuse most persistence compositions outright.
	{
		tacticA: "defense-evasion", tacticB: "exfiltration",
		reason: "disabling defenses then exfiltrating removes the egress observability this exfiltration step's safe rating assumed",
	},
	{
		tacticA: "defense-evasion", tacticB: "lateral-movement",
		reason: "disabling defenses then moving laterally removes the observability and blast-radius containment this lateral-movement step's safe rating assumed",
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
