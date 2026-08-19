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
	TechniqueID string `json:"techniqueId"`
	Name        string `json:"name"`
	Framework   string `json:"framework"`
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
// agentOS is "windows", "linux", or "darwin" — used to select the correct ART
// atomic variants for platform-aware scenarios. Pass "" to default to "windows".
// Modes are checked in priority order (see Scenario type comment). Every built
// step is then labelled with its curated resource profile so the agent scheduler
// can run independent steps concurrently; unlabeled steps stay serial. The
// second return value is only ever non-empty for a caldera_abilities scenario —
// the configured ability IDs that never became a step (not found in the live
// Caldera library, or no Windows-compatible executor), so a caller can make
// them visible instead of letting them vanish silently between "N configured"
// and "M actually ran".
func BuildSteps(sc *Scenario, calderaURL, calderaKey string, artStore *ARTStore, agentOS string) ([]ScenarioStep, []CalderaSkippedAbility, error) {
	steps, skipped, err := buildStepsRaw(sc, calderaURL, calderaKey, artStore, agentOS)
	if err != nil {
		return nil, skipped, err
	}
	AttachProfiles(steps)
	return steps, skipped, nil
}

// buildStepsRaw produces concrete steps without resource labels.
func buildStepsRaw(sc *Scenario, calderaURL, calderaKey string, artStore *ARTStore, agentOS string) ([]ScenarioStep, []CalderaSkippedAbility, error) {
	if agentOS == "" {
		agentOS = "windows"
	}
	if calderaURL != "" {
		if sc.CalderaAllWindows {
			steps, err := buildCalderaAllWindowsSteps(calderaURL, calderaKey)
			return steps, nil, err
		}
		if len(sc.CalderaAbilities) > 0 {
			return buildCalderaAbilitiesSteps(sc.CalderaAbilities, calderaURL, calderaKey)
		}
		if sc.CalderaAdversaryID != "" {
			steps, err := buildCalderaAdversarySteps(sc.CalderaAdversaryID, calderaURL, calderaKey)
			return steps, nil, err
		}
	}
	if sc.ARTAllWindows {
		if artStore == nil {
			return nil, nil, fmt.Errorf("ART store not available — set ART_DIR to a directory containing ART atomic YAML files")
		}
		steps, err := buildARTPlatformSteps("windows", artStore)
		return steps, nil, err
	}
	if sc.ARTAllPlatform {
		if artStore == nil {
			return nil, nil, fmt.Errorf("ART store not available — set ART_DIR to a directory containing ART atomic YAML files")
		}
		steps, err := buildARTPlatformSteps(agentOS, artStore)
		return steps, nil, err
	}
	if len(sc.ARTTechniques) > 0 {
		if artStore == nil {
			return nil, nil, fmt.Errorf("ART store not available — set ART_DIR to a directory containing ART atomic YAML files")
		}
		steps, err := buildARTTechniquesSteps(sc.ARTTechniques, artStore, agentOS)
		return steps, nil, err
	}
	out := make([]ScenarioStep, 0, len(sc.Steps))
	for _, s := range sc.Steps {
		built, err := buildStep(s, calderaURL, calderaKey, artStore, agentOS)
		if err != nil {
			return nil, nil, fmt.Errorf("step %q: %w", s.Name, err)
		}
		out = append(out, built)
	}
	return out, nil, nil
}

func buildStep(s Step, calderaURL, calderaKey string, artStore *ARTStore, agentOS string) (ScenarioStep, error) {
	executor := s.Executor
	if executor == "" {
		if agentOS == "linux" || agentOS == "darwin" {
			executor = "bash"
		} else {
			executor = "powershell"
		}
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
			artSteps := artStore.GetStepsByPlatform(s.TechniqueID, agentOS)
			idx := s.TestIndex
			if idx < 0 || idx >= len(artSteps) {
				idx = 0
			}
			if len(artSteps) > 0 {
				m := artStore.materialize(artSteps[idx])
				command = m.Command
				artPayloads = m.Payloads
				if m.Executor != "" {
					executor = m.Executor
				}
			}
		}
		if command == "" {
			if agentOS == "linux" || agentOS == "darwin" {
				command = fmt.Sprintf(`echo "SKIP: ART technique %s not in local store for %s"`, s.TechniqueID, agentOS)
			} else {
				command = fmt.Sprintf(`Write-Output "SKIP: ART technique %s not in local store"`, s.TechniqueID)
			}
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
		RequiresPriv: s.RequiresPriv.Effective(),
	}, nil
}

// ── ART Local Store Modes ──────────────────────────────────────────────────────

// buildARTPlatformSteps runs every atomic test for every technique that has
// at least one step on the given platform -- true depth, not just breadth.
// Delegates to buildARTTechniquesSteps (the same expansion the "Selective"
// scenario/operator-subset dispatch path already uses and already tests)
// rather than duplicating its per-technique atomic-expansion loop.
func buildARTPlatformSteps(platform string, artStore *ARTStore) ([]ScenarioStep, error) {
	techniques := artStore.ListTechniquesByPlatform(platform)
	if len(techniques) == 0 {
		return nil, fmt.Errorf("ART store has no %s steps — verify ART_DIR was loaded at startup", platform)
	}
	return buildARTTechniquesSteps(techniques, artStore, platform)
}

func buildARTTechniquesSteps(techniques []string, artStore *ARTStore, platform string) ([]ScenarioStep, error) {
	if platform == "" {
		platform = "windows"
	}
	// Dedup by normalized technique ID before expanding. Callers (operator-
	// selected subsets, campaigns, generated packs) don't all guarantee a
	// unique list, and expanding the same technique's full atomic-test set
	// twice would dispatch identical steps twice in one run.
	var steps []ScenarioStep
	seen := make(map[string]bool, len(techniques))
	for _, t := range techniques {
		id := strings.ToUpper(strings.TrimSpace(t))
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		s := artStore.GetStepsByPlatform(id, platform)
		if len(s) == 0 {
			log.Printf("[ART] no %s steps for %s — skipped", platform, t)
			continue
		}
		for _, st := range s {
			steps = append(steps, artStore.materialize(st))
		}
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("ART: no %s steps found for any of the %d requested techniques", platform, len(techniques))
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
	// Privilege is Caldera's own execution-context field on the ability
	// (not per-executor). Confirmed via a live Caldera instance
	// (ghcr.io/mitre/caldera:latest, /api/v2/abilities): exactly two
	// observed values, "Elevated" and "" (empty = no requirement).
	Privilege string `json:"privilege"`
}

// mapCalderaElevation translates Caldera's raw ability-level privilege
// string into this platform's framework-agnostic privilege tier (PrivSpec).
// This is the Caldera-specific half of the import normalization boundary,
// mirroring mapARTElevation in art.go — nothing downstream of the
// buildCaldera* functions ever sees Caldera's raw "Elevated"/"" strings
// again, only PrivSpec. Any value other than "Elevated" (including unknown
// future values) is treated as unprivileged rather than silently escalating.
func mapCalderaElevation(privilege string) PrivSpec {
	if privilege == "Elevated" {
		return PrivSpec{Minimum: "admin"}
	}
	return PrivSpec{Minimum: "user"}
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
			TaskID:       TaskID(techniqueID, ab.Name),
			TechniqueID:  techniqueID,
			Name:         ab.Name,
			Framework:    "caldera",
			Executor:     "powershell",
			Command:      cmd,
			TimeoutSec:   60,
			Fidelity:     calderaStepFidelity(*ab),
			RequiresPriv: mapCalderaElevation(ab.Privilege).Effective(),
		})
	}

	if len(steps) == 0 {
		return nil, fmt.Errorf("adversary %s yielded no executable steps for Windows platform", adversaryID)
	}
	return steps, nil
}

// CalderaSkippedAbility explains why a configured caldera_abilities entry
// never became a dispatched step. Surfaced up through BuildSteps so the
// operator can see WHICH ids were dropped and WHY, instead of just noticing
// the run's total came in lower than the scenario's configured count.
type CalderaSkippedAbility struct {
	AbilityID   string // as configured in the scenario YAML
	Name        string // ability name, only known if the id resolved
	TechniqueID string // only known if the id resolved
	Reason      string
}

// buildCalderaAbilitiesSteps runs a specific admin-chosen list of ability IDs.
func buildCalderaAbilitiesSteps(abilityIDs []string, calderaURL, apiKey string) ([]ScenarioStep, []CalderaSkippedAbility, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	base := strings.TrimRight(calderaURL, "/")

	var steps []ScenarioStep
	var skipped []CalderaSkippedAbility
	for _, id := range abilityIDs {
		ab, err := fetchCalderaAbilityFull(client, base, apiKey, id)
		if err != nil {
			log.Printf("[caldera] ability %s: not found in Caldera library — skipped (%v)", id, err)
			skipped = append(skipped, CalderaSkippedAbility{AbilityID: id, Reason: "not found in Caldera library"})
			continue
		}
		cmd := pickExecutorCommand(ab.Executors, "psh")
		if cmd == "" {
			techniqueID := ab.TechniqueID
			if techniqueID == "" {
				techniqueID = ab.Tactic
			}
			log.Printf("[caldera] ability %s (%q): no Windows-compatible executor — skipped", id, ab.Name)
			skipped = append(skipped, CalderaSkippedAbility{
				AbilityID: id, Name: ab.Name, TechniqueID: techniqueID,
				Reason: "no Windows-compatible executor",
			})
			continue
		}
		techniqueID := ab.TechniqueID
		if techniqueID == "" {
			techniqueID = ab.Tactic
		}
		steps = append(steps, ScenarioStep{
			TaskID:       TaskID(techniqueID, ab.Name),
			TechniqueID:  techniqueID,
			Name:         ab.Name,
			Framework:    "caldera",
			Executor:     "powershell",
			Command:      cmd,
			TimeoutSec:   60,
			Fidelity:     calderaStepFidelity(*ab),
			RequiresPriv: mapCalderaElevation(ab.Privilege).Effective(),
		})
	}
	if len(steps) == 0 {
		return nil, skipped, fmt.Errorf(
			"none of the %d ability IDs in caldera_abilities had a Windows executor in your Caldera instance. "+
				"Browse real IDs at: GET /api/v2/abilities (KEY: <your-api-key>) and update the scenario YAML",
			len(abilityIDs))
	}
	if len(skipped) > 0 {
		log.Printf("[caldera] %d of %d configured ability(ies) skipped, %d dispatched", len(skipped), len(abilityIDs), len(steps))
	}
	return steps, skipped, nil
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
	abilities, err := fetchAllCalderaAbilities(calderaURL, apiKey)
	if err != nil {
		return nil, err
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
			TaskID:       TaskID(techniqueID, ab.Name),
			TechniqueID:  techniqueID,
			Name:         ab.Name,
			Framework:    "caldera",
			Executor:     "powershell",
			Command:      cmd,
			TimeoutSec:   60,
			Fidelity:     calderaStepFidelity(ab),
			RequiresPriv: mapCalderaElevation(ab.Privilege).Effective(),
		})
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("caldera returned no abilities with a Windows executor")
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
