package corpusaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"os"

	"github.com/audspect/bas/internal/scenario"
	"gopkg.in/yaml.v3"

	"audspect/agent/destructiveguard"
)

// ReviewedDecision is one human classification decision for a
// (technique_id, action_key) pair that destructiveguard flagged. Loaded
// from the checked-in execclass_reviewed.yaml.
type ReviewedDecision struct {
	TechniqueID string                  `yaml:"technique_id"`
	ActionKey   string                  `yaml:"action_key"`
	Class       scenario.ExecutionClass `yaml:"class"`
	// CommandHash pins this decision to the exact command text it was
	// reviewed against -- if the live corpus's command for this pair
	// changes, the hash won't match and the item goes back to unresolved
	// rather than silently re-applying a decision nobody actually reviewed
	// against the new text.
	CommandHash string `yaml:"command_hash"`
	Reviewer    string `yaml:"reviewer"`
	ReviewedAt  string `yaml:"reviewed_at"`
	Note        string `yaml:"note"`
}

// CommandHash returns a stable fingerprint of a command string, used to
// detect when a reviewed decision's underlying command has drifted.
func CommandHash(command string) string {
	sum := sha256.Sum256([]byte(command))
	return hex.EncodeToString(sum[:])
}

// LoadReviewedDecisions reads the human-reviewed exception queue. A
// missing file is treated as "no decisions yet" (empty, no error) -- the
// first run against a fresh checkout has nothing reviewed yet, which is
// expected, not a failure.
func LoadReviewedDecisions(path string) ([]ReviewedDecision, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []ReviewedDecision
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

type reviewedKey struct{ tech, key string }

// Triage classifies every KeyedItem: skips anything the hand-authored
// catalog already covers (AlreadyCatalogued), runs destructiveguard.Classify
// on the rest, and merges in human decisions from reviewed for anything
// flagged destructive. A non-destructive destructiveguard verdict promotes
// an item straight to classified with no human decision needed --
// destructiveguard remains an independent runtime backstop regardless (see
// the design doc's Promotion rule).
func Triage(items []KeyedItem, reviewed []ReviewedDecision) []ClassifiedItem {
	byKey := make(map[reviewedKey]ReviewedDecision, len(reviewed))
	for _, r := range reviewed {
		byKey[reviewedKey{r.TechniqueID, r.ActionKey}] = r
	}

	out := make([]ClassifiedItem, 0, len(items))
	for _, it := range items {
		if AlreadyCatalogued(it.TechniqueID, it.ActionKey) {
			out = append(out, ClassifiedItem{KeyedItem: it, Status: StatusAlreadyHandAuthored})
			continue
		}
		switch destructiveguard.Classify(it.Command) {
		case destructiveguard.ClassNonDestructive:
			out = append(out, ClassifiedItem{
				KeyedItem: it, Status: StatusClassified,
				Class:             scenario.ClassNonDestructive,
				DestructiveAction: it.ActionKey,
				BlastRadius:       "no destructiveguard pattern match; destructiveguard remains an independent runtime backstop at dispatch time",
			})
		case destructiveguard.ClassDestructive:
			r, ok := byKey[reviewedKey{it.TechniqueID, it.ActionKey}]
			if ok && r.CommandHash == CommandHash(it.Command) {
				out = append(out, ClassifiedItem{
					KeyedItem: it, Status: StatusClassified,
					Class:             r.Class,
					DestructiveAction: it.ActionKey,
					BlastRadius:       r.Note,
				})
			} else {
				out = append(out, ClassifiedItem{KeyedItem: it, Status: StatusUnresolved})
			}
		}
	}
	return out
}
