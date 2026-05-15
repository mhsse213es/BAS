package scenario

// Step is a single ATT&CK technique execution within a scenario.
type Step struct {
	Name        string `yaml:"name"                  json:"name"`
	TechniqueID string `yaml:"technique_id"          json:"techniqueId"`
	Framework   string `yaml:"framework"             json:"framework"`
	Command     string `yaml:"command,omitempty"     json:"command,omitempty"`
	AbilityID   string `yaml:"ability_id,omitempty"  json:"abilityId,omitempty"`
	TestIndex   int    `yaml:"test_index"            json:"testIndex"`
	Executor    string `yaml:"executor,omitempty"    json:"executor,omitempty"`
	TimeoutSec  int    `yaml:"timeout_sec,omitempty" json:"timeoutSec,omitempty"`
}

// Scenario is a replayable named attack chain loaded from a YAML file.
type Scenario struct {
	ID          string   `yaml:"id"          json:"id"`
	Name        string   `yaml:"name"        json:"name"`
	Description string   `yaml:"description" json:"description"`
	Author      string   `yaml:"author,omitempty" json:"author,omitempty"`
	Tags        []string `yaml:"tags"        json:"tags"`
	MITREPhases []string `yaml:"mitre_phases" json:"mitrePhases"`
	Steps       []Step   `yaml:"steps"       json:"steps"`
}

// ScenarioCommand is the payload sent to an agent via WebSocket to execute a scenario.
type ScenarioCommand struct {
	RunID      string   `json:"runId"`
	ScenarioID string   `json:"scenarioId"`
	Name       string   `json:"name"`
	Steps      []Step   `json:"steps"`
}
