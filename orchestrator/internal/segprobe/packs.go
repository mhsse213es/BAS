package segprobe

import (
	"errors"
	"fmt"
)

// ErrUnknownPack is returned for any pack ID outside the registry. Client input
// never becomes a file path: a pack ID selects a fixed scenario file and a
// fixed rules file from this table, and nothing else.
var ErrUnknownPack = errors.New("unknown segmentation pack")

// Pack is one scenario pack the lab can run.
type Pack struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	ScenarioFile string `json:"-"`
	RulesFile    string `json:"-"`
}

var packRegistry = []Pack{
	{
		ID:           "swift-isolation",
		Name:         "SWIFT secure zone isolation",
		Description:  "Corporate IT and the SWIFT zone must not reach each other. Same-zone positive control.",
		ScenarioFile: "swift-isolation.yaml",
		RulesFile:    "swift.sh",
	},
	{
		ID:           "cde-atm-isolation",
		Name:         "CDE and ATM management isolation",
		Description:  "Corporate IT must not reach the CDE or ATM management. The core app is refused by a REJECT rule.",
		ScenarioFile: "cde-atm-isolation.yaml",
		RulesFile:    "cde-atm.sh",
	},
	{
		ID:           "core-banking-tiering",
		Name:         "Core banking tiering",
		Description:  "Only the app tier reaches the core database, and only on 5432.",
		ScenarioFile: "core-banking-tiering.yaml",
		RulesFile:    "core-banking.sh",
	},
}

// Packs returns the registry in display order.
func Packs() []Pack {
	out := make([]Pack, len(packRegistry))
	copy(out, packRegistry)
	return out
}

// LookupPack returns the registered pack with this ID.
func LookupPack(id string) (Pack, error) {
	for _, p := range packRegistry {
		if p.ID == id {
			return p, nil
		}
	}
	return Pack{}, fmt.Errorf("%w: %q", ErrUnknownPack, id)
}

// isRegisteredRulesFile reports whether a rules file name belongs to a pack.
func isRegisteredRulesFile(name string) bool {
	for _, p := range packRegistry {
		if p.RulesFile == name {
			return true
		}
	}
	return false
}
