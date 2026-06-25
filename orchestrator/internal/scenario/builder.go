package scenario

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// safeID allows only alphanumeric characters, hyphens, and underscores (max 128 chars).
// This prevents path traversal when IDs are interpolated into Caldera API URLs.
var safeID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

// TaskID generates a stable 8-char hex ID for a step.
// Used to correlate agent ExecResults back to their YAML Step.
func TaskID(techniqueID, name string) string {
	h := sha256.Sum256([]byte(techniqueID + "|" + name))
	return hex.EncodeToString(h[:])[:8]
}

// StepMeta is the per-task metadata the server retains after dispatch so it can
// interpret results from dynamically-built steps (ART/Caldera modes), whose
// definitions are NOT stored in the scenario's static Steps. Persisted with the
// run and read back when the agent returns results.
type StepMeta struct {
	TechniqueID      string       `json:"techniqueId"`
	Name             string       `json:"name"`
	Framework        string       `json:"framework"`
	// Variant fields — populated only for variant steps (BaseTaskID non-empty).
	// Persisted in scenario_runs.step_meta so the result processor can write
	// scenario_variant_results without re-querying at submission time.
	BaseTaskID       string       `json:"baseTaskId,omitempty"`
	VariantSpec      *VariantSpec `json:"variantSpec,omitempty"`
	ProxyTechniqueID string       `json:"proxyTechniqueId,omitempty"`
}

// BuildStepMeta builds a TaskID→StepMeta lookup from the steps actually
// dispatched to the agent, capturing the technique, name, framework and (for
// variant steps) the base TaskID + VariantSpec needed to write variant findings.
func BuildStepMeta(steps []ScenarioStep) map[string]StepMeta {
	m := make(map[string]StepMeta, len(steps))
	for _, s := range steps {
		meta := StepMeta{
			TechniqueID:      s.TechniqueID,
			Name:             s.Name,
			Framework:        s.Framework,
			BaseTaskID:       s.BaseTaskID,
			VariantSpec:      s.VariantSpecRef,
			ProxyTechniqueID: s.ProxyTechniqueID,
		}
		m[s.TaskID] = meta
	}
	return m
}

// BuildSteps converts a Scenario into concrete ScenarioSteps the agent executes.
// Modes are checked in priority order (see Scenario type comment). Every built
// step is then labelled with its curated resource profile so the agent scheduler
// can run independent steps concurrently; unlabeled steps stay serial.
func BuildSteps(sc *Scenario, calderaURL, calderaKey string, artStore *ARTStore) ([]ScenarioStep, error) {
	steps, err := buildStepsRaw(sc, calderaURL, calderaKey, artStore)
	if err != nil {
		return nil, err
	}
	AttachProfiles(steps)
	return steps, nil
}

// buildStepsRaw produces concrete steps without resource labels.
func buildStepsRaw(sc *Scenario, calderaURL, calderaKey string, artStore *ARTStore) ([]ScenarioStep, error) {
	if calderaURL != "" {
		if sc.CalderaAllWindows {
			return buildCalderaAllWindowsSteps(calderaURL, calderaKey)
		}
		if len(sc.CalderaAbilities) > 0 {
			return buildCalderaAbilitiesSteps(sc.CalderaAbilities, calderaURL, calderaKey)
		}
		if sc.CalderaAdversaryID != "" {
			return buildCalderaAdversarySteps(sc.CalderaAdversaryID, calderaURL, calderaKey)
		}
	}
	if sc.ARTAllWindows {
		if artStore == nil {
			return nil, fmt.Errorf("ART store not available — set ART_DIR to a directory containing ART atomic YAML files")
		}
		return buildARTAllWindowsSteps(artStore)
	}
	if len(sc.ARTTechniques) > 0 {
		if artStore == nil {
			return nil, fmt.Errorf("ART store not available — set ART_DIR to a directory containing ART atomic YAML files")
		}
		return buildARTTechniquesSteps(sc.ARTTechniques, artStore)
	}
	out := make([]ScenarioStep, 0, len(sc.Steps))
	for _, s := range sc.Steps {
		built, err := buildStep(s, calderaURL, calderaKey, artStore)
		if err != nil {
			return nil, fmt.Errorf("step %q: %w", s.Name, err)
		}
		out = append(out, built)
	}
	return out, nil
}

func buildStep(s Step, calderaURL, calderaKey string, artStore *ARTStore) (ScenarioStep, error) {
	executor := s.Executor
	if executor == "" {
		executor = "powershell"
	}
	timeout := s.TimeoutSec
	if timeout == 0 {
		timeout = 120
	}

	var command string
	var artPayloads []Payload
	switch s.Framework {
	case "art":
		if artStore != nil {
			artSteps := artStore.GetSteps(s.TechniqueID)
			idx := s.TestIndex
			if idx < 0 || idx >= len(artSteps) {
				idx = 0
			}
			if len(artSteps) > 0 {
				// materialize ships any required external payloads (or turns the
				// step into a clean SKIP if a payload is missing).
				m := artStore.materialize(artSteps[idx])
				command = m.Command
				artPayloads = m.Payloads
				if m.Executor != "" {
					executor = m.Executor
				}
			}
		}
		if command == "" {
			command = fmt.Sprintf(`Write-Output "SKIP: ART technique %s not in local store"`, s.TechniqueID)
		}
	case "caldera":
		// NOTE: this static-YAML path resolves only the command; unlike the
		// dynamic build paths it does NOT auto-detect ability payloads. If a
		// caldera step ships real payloads, declare `fidelity: lab-only` in the
		// scenario YAML — it is propagated via Step.Fidelity below.
		command = buildCalderaCommand(s, calderaURL, calderaKey)
	default: // "custom" or unset
		command = s.Command
		if command == "" {
			command = fmt.Sprintf(`Write-Output "SKIP: No command defined for step '%s'"`, s.Name)
		}
	}

	// Convert YAMLPayload → wire Payload (same shape, separate type).
	var payloads []Payload
	for _, p := range s.Payloads {
		payloads = append(payloads, Payload{Name: p.Name, Content: p.Content})
	}
	payloads = append(payloads, artPayloads...)

	framework := s.Framework
	if framework == "" {
		framework = "custom"
	}
	return ScenarioStep{
		TaskID:       TaskID(s.TechniqueID, s.Name),
		TechniqueID:  s.TechniqueID,
		Name:         s.Name,
		Framework:    framework,
		Executor:     executor,
		Command:      command,
		TimeoutSec:   timeout,
		Payloads:     payloads,
		Cleanup:      s.Cleanup,
		Fidelity:     s.Fidelity,
		RequiresPriv: s.RequiresPriv,
	}, nil
}

// ── ART Local Store Modes ──────────────────────────────────────────────────────

func buildARTAllWindowsSteps(artStore *ARTStore) ([]ScenarioStep, error) {
	techniques := artStore.ListTechniques()
	if len(techniques) == 0 {
		return nil, fmt.Errorf("ART store is empty — verify ART_DIR was loaded at startup")
	}
	// Breadth sweep: dispatch ONE representative atomic per technique (the first
	// Windows test), not every test. Running all tests across all techniques is
	// well over a thousand steps and multi-hour on a single endpoint, which made
	// the sweep impractical and prone to being cancelled mid-run. One-per-technique
	// preserves full ATT&CK breadth while keeping the run bounded. Use the Selective
	// scenario to run every atomic for a chosen set of techniques (depth).
	steps := make([]ScenarioStep, 0, len(techniques))
	for _, t := range techniques {
		s := artStore.GetSteps(strings.ToUpper(strings.TrimSpace(t)))
		if len(s) == 0 {
			log.Printf("[ART] no Windows steps for %s — skipped", t)
			continue
		}
		steps = append(steps, artStore.materialize(s[0]))
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("ART: no Windows steps found across %d techniques", len(techniques))
	}
	return steps, nil
}

func buildARTTechniquesSteps(techniques []string, artStore *ARTStore) ([]ScenarioStep, error) {
	var steps []ScenarioStep
	for _, t := range techniques {
		s := artStore.GetSteps(strings.ToUpper(strings.TrimSpace(t)))
		if len(s) == 0 {
			log.Printf("[ART] no Windows steps for %s — skipped", t)
			continue
		}
		for _, st := range s {
			// Ship required external payloads, or skip cleanly if missing.
			steps = append(steps, artStore.materialize(st))
		}
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("ART: no Windows steps found for any of the %d requested techniques", len(techniques))
	}
	return steps, nil
}

// buildCalderaCommand returns the ability command from Caldera API,
// falling back to the YAML command, then a skip message.
func buildCalderaCommand(s Step, calderaURL, calderaKey string) string {
	// Use YAML command if no Caldera configured
	if calderaURL == "" {
		if s.Command != "" {
			return s.Command
		}
		return fmt.Sprintf(
			`Write-Output "SKIP: Caldera not configured — set CALDERA_URL to enable ability %s"`,
			s.AbilityID)
	}

	if s.AbilityID != "" {
		if cmd, err := fetchCalderaCommand(calderaURL, calderaKey, s.AbilityID, s.Executor); err == nil && cmd != "" {
			return cmd
		}
	}

	// Fall back to inline YAML command
	if s.Command != "" {
		return s.Command
	}
	return fmt.Sprintf(`Write-Output "SKIP: Caldera ability %s not found"`, s.AbilityID)
}

// ── Caldera REST API ──────────────────────────────────────────────────────────

// calderaExecutor is one platform executor of a Caldera ability. Payloads lists
// the files the ability stages on the target; a non-empty list means the ability
// ships real tooling and must be gated to lab mode.
type calderaExecutor struct {
	Platform string   `json:"platform"`
	Name     string   `json:"name"`
	Command  string   `json:"command"`
	Payloads []string `json:"payloads"`
}

type calderaAbility struct {
	AbilityID string            `json:"ability_id"`
	Executors []calderaExecutor `json:"executors"`
}

func fetchCalderaCommand(calderaURL, apiKey, abilityID, preferredExecutor string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	base := strings.TrimRight(calderaURL, "/")

	// Try single-ability endpoint (Caldera v5+)
	if cmd, err := calderaGet(client, base+"/api/v2/abilities/"+abilityID, apiKey, preferredExecutor); err == nil {
		return cmd, nil
	}

	// Fall back to listing all abilities
	req, _ := http.NewRequest("GET", base+"/api/v2/abilities", nil)
	if apiKey != "" {
		req.Header.Set("KEY", apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var abilities []calderaAbility
	if err := json.Unmarshal(body, &abilities); err != nil {
		return "", err
	}
	for _, ab := range abilities {
		if ab.AbilityID == abilityID {
			return pickExecutorCommand(ab.Executors, preferredExecutor), nil
		}
	}
	return "", fmt.Errorf("ability %s not found", abilityID)
}

func calderaGet(client *http.Client, url, apiKey, preferredExecutor string) (string, error) {
	req, _ := http.NewRequest("GET", url, nil)
	if apiKey != "" {
		req.Header.Set("KEY", apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var ab calderaAbility
	if err := json.Unmarshal(body, &ab); err != nil {
		return "", err
	}
	return pickExecutorCommand(ab.Executors, preferredExecutor), nil
}

func pickExecutorCommand(executors []calderaExecutor, preferred string) string {
	if preferred == "" {
		preferred = "psh"
	}
	// First try the preferred executor, then psh/powershell, then first available
	for _, e := range executors {
		if e.Name == preferred {
			return e.Command
		}
	}
	for _, e := range executors {
		if e.Name == "psh" || e.Name == "powershell" {
			return e.Command
		}
	}
	if len(executors) > 0 {
		return executors[0].Command
	}
	return ""
}

// ── Caldera Adversary Expansion ───────────────────────────────────────────────

type calderaAdversary struct {
	AdversaryID    string   `json:"adversary_id"`
	Name           string   `json:"name"`
	AtomicOrdering []string `json:"atomic_ordering"`
}

type calderaAbilityFull struct {
	AbilityID   string            `json:"ability_id"`
	Name        string            `json:"name"`
	TechniqueID string            `json:"technique_id"`
	Tactic      string            `json:"tactic"`
	Executors   []calderaExecutor `json:"executors"`
}

// buildCalderaAdversarySteps fetches an adversary profile from Caldera,
// then fetches each ability in its atomic_ordering and builds a ScenarioStep
// for every ability that has a Windows (psh/powershell/cmd) executor.
func buildCalderaAdversarySteps(adversaryID, calderaURL, apiKey string) ([]ScenarioStep, error) {
	if !safeID.MatchString(adversaryID) {
		return nil, fmt.Errorf("invalid adversary ID %q: must be alphanumeric/hyphen/underscore", adversaryID)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	base := strings.TrimRight(calderaURL, "/")

	req, _ := http.NewRequest("GET", base+"/api/v2/adversaries/"+adversaryID, nil)
	if apiKey != "" {
		req.Header.Set("KEY", apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch adversary: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch adversary: HTTP %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var adversary calderaAdversary
	if err := json.Unmarshal(body, &adversary); err != nil {
		return nil, fmt.Errorf("parse adversary: %w", err)
	}
	if len(adversary.AtomicOrdering) == 0 {
		return nil, fmt.Errorf("adversary %s has no abilities in atomic_ordering", adversaryID)
	}

	var steps []ScenarioStep
	for _, abilityID := range adversary.AtomicOrdering {
		ab, err := fetchCalderaAbilityFull(client, base, apiKey, abilityID)
		if err != nil {
			continue
		}
		cmd := pickExecutorCommand(ab.Executors, "psh")
		if cmd == "" {
			continue
		}
		techniqueID := ab.TechniqueID
		if techniqueID == "" {
			techniqueID = ab.Tactic
		}
		steps = append(steps, ScenarioStep{
			TaskID:      TaskID(techniqueID, ab.Name),
			TechniqueID: techniqueID,
			Name:        ab.Name,
			Framework:   "caldera",
			Executor:    "powershell",
			Command:     cmd,
			TimeoutSec:  60,
			Fidelity:    calderaStepFidelity(*ab),
		})
	}

	if len(steps) == 0 {
		return nil, fmt.Errorf("adversary %s yielded no executable steps for Windows platform", adversaryID)
	}
	return steps, nil
}

// buildCalderaAbilitiesSteps runs a specific admin-chosen list of ability IDs.
func buildCalderaAbilitiesSteps(abilityIDs []string, calderaURL, apiKey string) ([]ScenarioStep, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	base := strings.TrimRight(calderaURL, "/")

	var steps []ScenarioStep
	for _, id := range abilityIDs {
		ab, err := fetchCalderaAbilityFull(client, base, apiKey, id)
		if err != nil {
			continue
		}
		cmd := pickExecutorCommand(ab.Executors, "psh")
		if cmd == "" {
			continue
		}
		techniqueID := ab.TechniqueID
		if techniqueID == "" {
			techniqueID = ab.Tactic
		}
		steps = append(steps, ScenarioStep{
			TaskID:      TaskID(techniqueID, ab.Name),
			TechniqueID: techniqueID,
			Name:        ab.Name,
			Framework:   "caldera",
			Executor:    "powershell",
			Command:     cmd,
			TimeoutSec:  60,
			Fidelity:    calderaStepFidelity(*ab),
		})
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf(
			"none of the %d ability IDs in caldera_abilities had a Windows executor in your Caldera instance. "+
				"Browse real IDs at: GET /api/v2/abilities (KEY: <your-api-key>) and update the scenario YAML",
			len(abilityIDs))
	}
	return steps, nil
}

// calderaStepFidelity returns "lab-only" if any of the ability's executors ships
// a payload (real tooling), else "". Conservative: any payload across any executor
// gates the whole ability to lab mode.
func calderaStepFidelity(ab calderaAbilityFull) string {
	for _, e := range ab.Executors {
		if len(e.Payloads) > 0 {
			return "lab-only"
		}
	}
	return ""
}

// buildCalderaAllWindowsSteps fetches the entire Caldera ability library and
// returns a step for every ability that has a Windows executor.
func buildCalderaAllWindowsSteps(calderaURL, apiKey string) ([]ScenarioStep, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	base := strings.TrimRight(calderaURL, "/")

	req, _ := http.NewRequest("GET", base+"/api/v2/abilities", nil)
	if apiKey != "" {
		req.Header.Set("KEY", apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch all abilities: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch all abilities: HTTP %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)

	var abilities []calderaAbilityFull
	if err := json.Unmarshal(body, &abilities); err != nil {
		return nil, fmt.Errorf("parse abilities: %w", err)
	}

	var steps []ScenarioStep
	for _, ab := range abilities {
		cmd := pickExecutorCommand(ab.Executors, "psh")
		if cmd == "" {
			continue
		}
		techniqueID := ab.TechniqueID
		if techniqueID == "" {
			techniqueID = ab.Tactic
		}
		steps = append(steps, ScenarioStep{
			TaskID:      TaskID(techniqueID, ab.Name),
			TechniqueID: techniqueID,
			Name:        ab.Name,
			Framework:   "caldera",
			Executor:    "powershell",
			Command:     cmd,
			TimeoutSec:  60,
			Fidelity:    calderaStepFidelity(ab),
		})
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("Caldera returned no abilities with a Windows executor")
	}
	return steps, nil
}

func fetchCalderaAbilityFull(client *http.Client, base, apiKey, abilityID string) (*calderaAbilityFull, error) {
	if !safeID.MatchString(abilityID) {
		return nil, fmt.Errorf("invalid ability ID %q: must be alphanumeric/hyphen/underscore", abilityID)
	}
	req, _ := http.NewRequest("GET", base+"/api/v2/abilities/"+abilityID, nil)
	if apiKey != "" {
		req.Header.Set("KEY", apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var ab calderaAbilityFull
	if err := json.Unmarshal(body, &ab); err != nil {
		return nil, err
	}
	return &ab, nil
}
