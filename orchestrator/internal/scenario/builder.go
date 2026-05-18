package scenario

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// TaskID generates a stable 8-char hex ID for a step.
// Used to correlate agent ExecResults back to their YAML Step.
func TaskID(techniqueID, name string) string {
	h := sha256.Sum256([]byte(techniqueID + "|" + name))
	return hex.EncodeToString(h[:])[:8]
}

// BuildSteps converts a Scenario into concrete ScenarioSteps the agent executes.
// Modes are checked in priority order (see Scenario type comment).
func BuildSteps(sc *Scenario, calderaURL, calderaKey string) ([]ScenarioStep, error) {
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
		return buildARTAllWindowsSteps()
	}
	if len(sc.ARTTechniques) > 0 {
		return buildARTTechniquesSteps(sc.ARTTechniques)
	}
	out := make([]ScenarioStep, 0, len(sc.Steps))
	for _, s := range sc.Steps {
		built, err := buildStep(s, calderaURL, calderaKey)
		if err != nil {
			return nil, fmt.Errorf("step %q: %w", s.Name, err)
		}
		out = append(out, built)
	}
	return out, nil
}

func buildStep(s Step, calderaURL, calderaKey string) (ScenarioStep, error) {
	executor := s.Executor
	if executor == "" {
		executor = "powershell"
	}
	timeout := s.TimeoutSec
	if timeout == 0 {
		timeout = 120
	}

	var command string
	switch s.Framework {
	case "art":
		command = buildARTCommand(s)
	case "caldera":
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

	return ScenarioStep{
		TaskID:      TaskID(s.TechniqueID, s.Name),
		TechniqueID: s.TechniqueID,
		Name:        s.Name,
		Executor:    executor,
		Command:     command,
		TimeoutSec:  timeout,
		Payloads:    payloads,
		Cleanup:     s.Cleanup,
	}, nil
}

// buildARTCommand generates the Invoke-AtomicTest PowerShell command for a single
// hardcoded step (framework: art with test_index set).
func buildARTCommand(s Step) string {
	timeout := s.TimeoutSec
	if timeout == 0 {
		timeout = 120
	}
	return fmt.Sprintf(
		`try {`+
			` Invoke-AtomicTest %s -TestNumbers @(%d) -Confirm:$false -TimeoutSeconds %d 2>&1`+
			` } catch { Write-Output "ART_ERROR: $_" }`,
		s.TechniqueID, s.TestIndex, timeout)
}

// ── Atomic Red Team Dynamic Modes ─────────────────────────────────────────────

const artIndexURL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/Indexes-CSV/index.csv"

// buildARTAllWindowsSteps fetches the ART index from GitHub and builds one step
// per technique that has at least one PowerShell or command_prompt test.
// Omitting -TestNumbers runs ALL tests for that technique automatically.
func buildARTAllWindowsSteps() ([]ScenarioStep, error) {
	techniques, err := fetchARTWindowsTechniques()
	if err != nil {
		return nil, err
	}
	return buildARTTechniquesSteps(techniques)
}

// buildARTTechniquesSteps builds one step per technique in the provided list.
// Each step runs ALL atomic tests for that technique via Invoke-AtomicTest.
func buildARTTechniquesSteps(techniques []string) ([]ScenarioStep, error) {
	if len(techniques) == 0 {
		return nil, fmt.Errorf("ART: empty technique list")
	}
	steps := make([]ScenarioStep, 0, len(techniques))
	for _, t := range techniques {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		steps = append(steps, ScenarioStep{
			TaskID:      TaskID(t, "art-"+t),
			TechniqueID: t,
			Name:        "ART: " + t,
			Executor:    "powershell",
			// No -TestNumbers → runs every atomic test for this technique.
			// -GetPrereqs installs dependencies before execution.
			Command: fmt.Sprintf(
				`try {`+
					` Invoke-AtomicTest %s -GetPrereqs -Confirm:$false 2>&1;`+
					` Invoke-AtomicTest %s -Confirm:$false -TimeoutSeconds 120 2>&1`+
					` } catch { Write-Output "ART_ERROR: $_" }`,
				t, t),
			TimeoutSec: 180,
		})
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("ART: no valid techniques to run")
	}
	return steps, nil
}

// fetchARTWindowsTechniques downloads the ART CSV index and returns all unique
// technique IDs that have at least one PowerShell or command_prompt test.
func fetchARTWindowsTechniques() ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(artIndexURL)
	if err != nil {
		return nil, fmt.Errorf("fetch ART index: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch ART index: HTTP %d", resp.StatusCode)
	}

	r := csv.NewReader(resp.Body)
	r.Read() // skip header row

	seen := make(map[string]bool)
	var techniques []string
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(record) < 5 {
			continue
		}
		techniqueID := strings.TrimSpace(record[0])
		executor := strings.ToLower(strings.TrimSpace(record[4]))
		if (executor == "powershell" || executor == "command_prompt") && !seen[techniqueID] {
			seen[techniqueID] = true
			techniques = append(techniques, techniqueID)
		}
	}

	if len(techniques) == 0 {
		return nil, fmt.Errorf("ART index returned no Windows techniques")
	}
	sort.Strings(techniques)
	return techniques, nil
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

type calderaAbility struct {
	AbilityID string `json:"ability_id"`
	Executors []struct {
		Platform string `json:"platform"`
		Name     string `json:"name"`
		Command  string `json:"command"`
	} `json:"executors"`
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

func pickExecutorCommand(executors []struct {
	Platform string `json:"platform"`
	Name     string `json:"name"`
	Command  string `json:"command"`
}, preferred string) string {
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
	AbilityID   string `json:"ability_id"`
	Name        string `json:"name"`
	TechniqueID string `json:"technique_id"`
	Tactic      string `json:"tactic"`
	Executors   []struct {
		Platform string `json:"platform"`
		Name     string `json:"name"`
		Command  string `json:"command"`
	} `json:"executors"`
}

// buildCalderaAdversarySteps fetches an adversary profile from Caldera,
// then fetches each ability in its atomic_ordering and builds a ScenarioStep
// for every ability that has a Windows (psh/powershell/cmd) executor.
// This replaces the static 5-step YAML with the full adversary ability set.
func buildCalderaAdversarySteps(adversaryID, calderaURL, apiKey string) ([]ScenarioStep, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	base := strings.TrimRight(calderaURL, "/")

	// 1. Fetch the adversary profile
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

	// 2. Fetch each ability and build a step
	var steps []ScenarioStep
	for _, abilityID := range adversary.AtomicOrdering {
		ab, err := fetchCalderaAbilityFull(client, base, apiKey, abilityID)
		if err != nil {
			// Non-fatal: skip abilities that can't be fetched
			continue
		}
		cmd := pickExecutorCommand(ab.Executors, "psh")
		if cmd == "" {
			// No Windows executor for this ability — skip
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
			Executor:    "powershell",
			Command:     cmd,
			TimeoutSec:  60,
		})
	}

	if len(steps) == 0 {
		return nil, fmt.Errorf("adversary %s yielded no executable steps for Windows platform", adversaryID)
	}
	return steps, nil
}

// buildCalderaAbilitiesSteps runs a specific admin-chosen list of ability IDs.
// Use this when the admin selects individual abilities from the Caldera library.
func buildCalderaAbilitiesSteps(abilityIDs []string, calderaURL, apiKey string) ([]ScenarioStep, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	base := strings.TrimRight(calderaURL, "/")

	var steps []ScenarioStep
	for _, id := range abilityIDs {
		ab, err := fetchCalderaAbilityFull(client, base, apiKey, id)
		if err != nil {
			continue // skip abilities that can't be fetched
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
			Executor:    "powershell",
			Command:     cmd,
			TimeoutSec:  60,
		})
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("none of the %d specified abilities had a Windows executor", len(abilityIDs))
	}
	return steps, nil
}

// buildCalderaAllWindowsSteps fetches the entire Caldera ability library and
// returns a step for every ability that has a Windows (psh/powershell/cmd) executor.
// This is the "run everything" mode — could be 500–2000+ steps depending on plugins loaded.
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
			continue // no Windows executor — skip
		}
		techniqueID := ab.TechniqueID
		if techniqueID == "" {
			techniqueID = ab.Tactic
		}
		steps = append(steps, ScenarioStep{
			TaskID:      TaskID(techniqueID, ab.Name),
			TechniqueID: techniqueID,
			Name:        ab.Name,
			Executor:    "powershell",
			Command:     cmd,
			TimeoutSec:  60,
		})
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("Caldera returned no abilities with a Windows executor")
	}
	return steps, nil
}

func fetchCalderaAbilityFull(client *http.Client, base, apiKey, abilityID string) (*calderaAbilityFull, error) {
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
