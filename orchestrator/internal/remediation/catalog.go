package remediation

import (
	"embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed catalog.yaml
var catalogFS embed.FS

// Tier is the remediation execution tier -- how much human gate a
// remediation needs before it runs. Tier 3 (scheduled/maintenance-window)
// is reserved for Sub-project 6 and must never appear in this catalog.
type Tier int

const (
	TierSafeAutomatic   Tier = 1
	TierConfirmRequired Tier = 2
	TierManualGuidance  Tier = 4
)

// CatalogEntry is one remediation definition. Exported so callers
// (internal/api's Finding-enrichment and orchestration code) can read its
// fields directly.
type CatalogEntry struct {
	ID                  string   `yaml:"id"`
	Title               string   `yaml:"title"`
	Description         string   `yaml:"description"`
	Category            string   `yaml:"category"`
	Tier                Tier     `yaml:"tier"`
	CheckID             string   `yaml:"check_id"`
	VerificationCheckID string   `yaml:"verification_check_id,omitempty"`
	SupportedOS         []string `yaml:"supported_os"`
	RequiresAdmin       bool     `yaml:"requires_admin,omitempty"`
	RequiresReboot      bool     `yaml:"requires_reboot,omitempty"`
	SupportsRollback    bool     `yaml:"supports_rollback,omitempty"`
	EstimatedTimeSec    int      `yaml:"estimated_time_sec,omitempty"`
	Executor            string   `yaml:"executor,omitempty"`
	Command             string   `yaml:"command,omitempty"`
	RollbackCommand     string   `yaml:"rollback_command,omitempty"`
	ManualSteps         []string `yaml:"manual_steps,omitempty"`
}

type catalogFile struct {
	Remediations []CatalogEntry `yaml:"remediations"`
}

// Catalog is the embedded, hand-curated set of remediation definitions,
// indexed by both id and check_id for O(1) lookup either way.
type Catalog struct {
	byID      map[string]CatalogEntry
	byCheckID map[string]CatalogEntry
}

// NewCatalog loads and validates the embedded catalog.yaml: unique id,
// non-empty check_id/supported_os, and the tier/command/manual_steps
// pairing (Tier 1/2 need a command and no manual_steps; Tier 4 needs
// manual_steps and no command) -- a violation is a load-time error, not a
// runtime surprise.
func NewCatalog() (*Catalog, error) {
	data, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("remediation: read catalog.yaml: %w", err)
	}
	var cf catalogFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("remediation: parse catalog.yaml: %w", err)
	}
	if len(cf.Remediations) == 0 {
		return nil, fmt.Errorf("remediation: no catalog entries loaded")
	}
	byID := make(map[string]CatalogEntry, len(cf.Remediations))
	byCheckID := make(map[string]CatalogEntry, len(cf.Remediations))
	for _, e := range cf.Remediations {
		if e.ID == "" || e.CheckID == "" || len(e.SupportedOS) == 0 {
			return nil, fmt.Errorf("remediation: entry missing id/check_id/supported_os: %+v", e)
		}
		if _, dup := byID[e.ID]; dup {
			return nil, fmt.Errorf("remediation: duplicate catalog id %q", e.ID)
		}
		switch e.Tier {
		case TierSafeAutomatic, TierConfirmRequired:
			if e.Command == "" {
				return nil, fmt.Errorf("remediation: tier 1/2 entry %q missing command", e.ID)
			}
			if len(e.ManualSteps) > 0 {
				return nil, fmt.Errorf("remediation: tier 1/2 entry %q must not have manual_steps", e.ID)
			}
		case TierManualGuidance:
			if e.Command != "" {
				return nil, fmt.Errorf("remediation: tier 4 entry %q must not have a command", e.ID)
			}
			if len(e.ManualSteps) == 0 {
				return nil, fmt.Errorf("remediation: tier 4 entry %q missing manual_steps", e.ID)
			}
		default:
			return nil, fmt.Errorf("remediation: entry %q has unsupported tier %d", e.ID, e.Tier)
		}
		byID[e.ID] = e
		byCheckID[e.CheckID] = e
	}
	return &Catalog{byID: byID, byCheckID: byCheckID}, nil
}

// Lookup finds the remediation catalog entry for a finding's check_id.
func (c *Catalog) Lookup(checkID string) (CatalogEntry, bool) {
	e, ok := c.byCheckID[checkID]
	return e, ok
}

// ByID finds a catalog entry by its own id (used once execution is
// requested with an explicit remediationId).
func (c *Catalog) ByID(id string) (CatalogEntry, bool) {
	e, ok := c.byID[id]
	return e, ok
}
