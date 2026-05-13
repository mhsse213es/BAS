package scenario

// Step is a single ATT&CK technique execution within a scenario.
type Step struct {
	Name        string `yaml:"name"`
	TechniqueID string `yaml:"technique_id"`
	Framework   string `yaml:"framework"`            // art | caldera | custom
	Command     string `yaml:"command,omitempty"`     // used by custom framework
	AbilityID   string `yaml:"ability_id,omitempty"` // Caldera ability UUID
	TestIndex   int    `yaml:"test_index"`            // ART atomic test index (0-based)
	Executor    string `yaml:"executor,omitempty"`    // powershell | bash | cmd (default: powershell)
	TimeoutSec  int    `yaml:"timeout_sec,omitempty"` // default: 30
}

// Scenario is a replayable named attack chain loaded from a YAML file.
type Scenario struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Author      string   `yaml:"author,omitempty"`
	Tags        []string `yaml:"tags"`
	MITREPhases []string `yaml:"mitre_phases"`
	Steps       []Step   `yaml:"steps"`
}

// ScenarioCommand is the payload sent to an agent via WebSocket to execute a scenario.
type ScenarioCommand struct {
	RunID      string   `json:"runId"`
	ScenarioID string   `json:"scenarioId"`
	Name       string   `json:"name"`
	Steps      []Step   `json:"steps"`
}
