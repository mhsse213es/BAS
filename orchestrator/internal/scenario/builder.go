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
	"sort"
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

// dedupeStepIdentity disambiguates steps that would otherwise share an
// identical (TechniqueID, Name) pair -- and therefore an identical TaskID,
// a pure content hash of the two. This is a real, legitimate case, not a
// hash collision: a Caldera adversary profile (or an ability list) commonly
// repeats the same ability -- a recon/discovery check, say -- at multiple
// points in its kill chain. Without this, two distinct step instances
// collapse onto one TaskID: SubmitScenarioResult's stepMap lookup
// misattributes one step's identity to the other, and the browser's live
// progress panel (keyed by taskId) silently overwrites one step's events
// with the other's, undercounting the run's real step total.
//
// Disambiguates by rewriting Name and TaskID together, never TaskID alone,
// so every downstream recomputation from (TechniqueID, Name) --
// scenario.Interpret's SimulationResult.ID chief among them -- stays
// consistent with what was actually dispatched instead of colliding all
// over again one layer down. Only the 2nd+ occurrence of any
// (TechniqueID, Name) pair is touched; the first keeps its original Name
// and TaskID unchanged, so a scenario with no duplicates builds
// byte-identical steps to before this function existed.
func dedupeStepIdentity(steps []ScenarioStep) {
	seen := make(map[string]int, len(steps))
	for i := range steps {
		key := steps[i].TechniqueID + "|" + steps[i].Name
		seen[key]++
		if n := seen[key]; n > 1 {
			steps[i].Name = fmt.Sprintf("%s (#%d)", steps[i].Name, n)
			steps[i].TaskID = TaskID(steps[i].TechniqueID, steps[i].Name)
		}
	}
}

// StepMeta is the per-task metadata the server retains after dispatch so it can
// interpret results from dynamically-built steps (ART/Caldera modes), whose
// definitions are NOT stored in the scenario's static Steps. Persisted with the
// run and read back when the agent returns results.
type StepMeta struct {
	TechniqueID string `json:"techniqueId"`
	Name        string `json:"name"`
	Framework   string `json:"framework"`
	// TCF Phase 1 §4.9 / plan amendment 7. Component + version pin the
	// mutable catalog a step was resolved from; ResolvedSHA256 is taken right
	// after BuildSteps (comparable on rebuild -> drift), CommandSHA256 is what
	// was actually sent (includes per-run artifact/sink-token substitution).
	Component        string `json:"component,omitempty"`
	ComponentVersion string `json:"componentVersion,omitempty"`
	Platform         string `json:"platform,omitempty"`
	ResolvedSHA256   string `json:"resolvedSha256,omitempty"`
	CommandSHA256    string `json:"commandSha256,omitempty"`
	// Variant fields — populated only for variant steps (BaseTaskID non-empty).
	// Persisted in scenario_runs.step_meta so the result processor can write
	// scenario_variant_results without re-querying at submission time.
	BaseTaskID       string       `json:"baseTaskId,omitempty"`
	VariantSpec      *VariantSpec `json:"variantSpec,omitempty"`
	ProxyTechniqueID string       `json:"proxyTechniqueId,omitempty"`
}

type ComponentVersions struct {
	ART     string
	Caldera string
}

// StepCommandSHA256 hashes canonical JSON of exactly what an agent executes.
func StepCommandSHA256(st ScenarioStep) string {
	type p struct {
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
	}
	ps := make([]p, 0, len(st.Payloads))
	for _, pl := range st.Payloads {
		h := sha256.Sum256([]byte(pl.Content))
		ps = append(ps, p{Name: pl.Name, SHA256: hex.EncodeToString(h[:])})
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].Name < ps[j].Name })
	b, _ := json.Marshal(struct {
		Executor string `json:"executor"`
		Command  string `json:"command"`
		Cleanup  string `json:"cleanup"`
		Payloads []p    `json:"payloads"`
	}{st.Executor, st.Command, st.Cleanup, ps})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ResolvedHashes snapshots per-step hashes right after BuildSteps, before
// any per-run substitution.
func ResolvedHashes(steps []ScenarioStep) map[string]string {
	out := make(map[string]string, len(steps))
	for _, st := range steps {
		out[st.TaskID] = StepCommandSHA256(st)
	}
	return out
}

// BuildStepMeta builds a TaskID→StepMeta lookup from the steps actually
// dispatched to the agent, capturing the technique, name, framework and (for
// variant steps) the base TaskID + VariantSpec needed to write variant findings.
func BuildStepMeta(steps []ScenarioStep, resolved map[string]string, cv ComponentVersions) map[string]StepMeta {
	m := make(map[string]StepMeta, len(steps))
	for _, st := range steps {
		meta := StepMeta{
			TechniqueID:      st.TechniqueID,
			Name:             st.Name,
			Framework:        st.Framework,
			BaseTaskID:       st.BaseTaskID,
			VariantSpec:      st.VariantSpecRef,
			ProxyTechniqueID: st.ProxyTechniqueID,
		}
		meta.Component = st.Framework
		switch st.Framework {
		case "art":
			meta.ComponentVersion = cv.ART
		case "caldera":
			meta.ComponentVersion = cv.Caldera
		}
		meta.Platform = st.Platform
		meta.ResolvedSHA256 = resolved[st.TaskID]
		meta.CommandSHA256 = StepCommandSHA256(st)
		m[st.TaskID] = meta
	}
	return m
}

// BuildSteps converts a Scenario into concrete ScenarioSteps the agent executes.
// agentOS is "windows", "linux", or "darwin" — used to select the correct ART
// atomic variants for platform-aware scenarios. Pass "" to default to "windows".
// Modes are checked in priority order (see Scenario type comment); whichever
// shorthand matches (if any) resolves first, and any explicit steps: entries
// are then always built and appended after it -- letting a scenario cover most
// techniques via a shorthand and hand-author the rest, instead of the two
// being mutually exclusive. An infrastructure-level error from the matched
// shorthand (ART store unavailable, Caldera unreachable, etc.) still aborts
// the whole build immediately, exactly as before; steps: is only appended
// after a successful (possibly partial) shorthand resolution. Every built
// step is then labelled with its curated resource profile so the agent
// scheduler can run independent steps concurrently; unlabeled steps stay
// serial. The second return value carries any configured ability/technique
// that never became a step (not found in the live Caldera library, no
// Windows-compatible executor, or no local ART atomic for the platform) --
// see CalderaSkippedAbility -- so a caller can make it visible instead of
// letting it vanish silently between "N configured" and "M actually ran".
// Only caldera_abilities, caldera_adversary_id, and art_techniques ever
// populate it: the other shorthand modes mean "everything the library has,"
// with no declared-vs-found gap to report.
func BuildSteps(sc *Scenario, calderaURL, calderaKey string, artStore *ARTStore, agentOS string) ([]ScenarioStep, []CalderaSkippedAbility, error) {
	steps, skipped, err := buildStepsRaw(sc, calderaURL, calderaKey, artStore, agentOS)
	if err != nil {
		return nil, skipped, err
	}
	dedupeStepIdentity(steps)
	AttachProfiles(steps)
	AttachExecutionClassifications(steps)
	return steps, skipped, nil
}

// buildStepsRaw produces concrete steps without resource labels.
func buildStepsRaw(sc *Scenario, calderaURL, calderaKey string, artStore *ARTStore, agentOS string) ([]ScenarioStep, []CalderaSkippedAbility, error) {
	if agentOS == "" {
		agentOS = "windows"
	}

	var steps []ScenarioStep
	var skipped []CalderaSkippedAbility
	switch {
	case calderaURL != "" && sc.CalderaAllWindows:
		s, err := buildCalderaAllWindowsSteps(calderaURL, calderaKey)
		if err != nil {
			return nil, nil, err
		}
		steps = s
	case calderaURL != "" && len(sc.CalderaAbilities) > 0:
		s, sk, err := buildCalderaAbilitiesSteps(sc.CalderaAbilities, calderaURL, calderaKey)
		if err != nil {
			return nil, sk, err
		}
		steps, skipped = s, sk
	case calderaURL != "" && sc.CalderaAdversaryID != "":
		s, sk, err := buildCalderaAdversarySteps(sc.CalderaAdversaryID, calderaURL, calderaKey)
		if err != nil {
			return nil, sk, err
		}
		steps, skipped = s, sk
	case sc.ARTAllWindows:
		if artStore == nil {
			return nil, nil, fmt.Errorf("ART store not available — set ART_DIR to a directory containing ART atomic YAML files")
		}
		s, err := buildARTPlatformSteps("windows", artStore)
		if err != nil {
			return nil, nil, err
		}
		steps = s
	case sc.ARTAllPlatform:
		if artStore == nil {
			return nil, nil, fmt.Errorf("ART store not available — set ART_DIR to a directory containing ART atomic YAML files")
		}
		s, err := buildARTPlatformSteps(agentOS, artStore)
		if err != nil {
			return nil, nil, err
		}
		steps = s
	// ARTSelectiveWindows/ARTSelectivePlatform default to the exact same
	// full-depth builder as ARTAllWindows/ARTAllPlatform above -- an operator
	// narrows the run via the Customize picker's technique subset, which
	// arrives here as ARTTechniques after the API handler clears these flags
	// (see RunScenario's subset-override logic), so this branch only ever
	// runs for the unmodified "everything" default.
	case sc.ARTSelectiveWindows:
		if artStore == nil {
			return nil, nil, fmt.Errorf("ART store not available — set ART_DIR to a directory containing ART atomic YAML files")
		}
		s, err := buildARTPlatformSteps("windows", artStore)
		if err != nil {
			return nil, nil, err
		}
		steps = s
	case sc.ARTSelectivePlatform:
		if artStore == nil {
			return nil, nil, fmt.Errorf("ART store not available — set ART_DIR to a directory containing ART atomic YAML files")
		}
		s, err := buildARTPlatformSteps(agentOS, artStore)
		if err != nil {
			return nil, nil, err
		}
		steps = s
	case len(sc.ARTTechniques) > 0:
		if artStore == nil {
			return nil, nil, fmt.Errorf("ART store not available — set ART_DIR to a directory containing ART atomic YAML files")
		}
		s, sk, err := buildARTTechniquesSteps(sc.ARTTechniques, artStore, agentOS)
		if err != nil {
			return nil, sk, err
		}
		steps, skipped = s, sk
	}

	// Explicit steps: entries always run in addition to whatever shorthand
	// mode (if any) already resolved above.
	for _, s := range sc.Steps {
		built, err := buildStep(s, calderaURL, calderaKey, artStore, agentOS)
		if err != nil {
			return nil, skipped, fmt.Errorf("step %q: %w", s.Name, err)
		}
		steps = append(steps, built)
	}
	return steps, skipped, nil
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
		ActionKey:    s.ActionKey,
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
	// techniques is sourced from ListTechniquesByPlatform, so every entry is
	// guaranteed to have at least one step -- the skipped list is always empty
	// here and deliberately discarded; this "everything available" sweep mode
	// has no declared-vs-found gap to surface (see buildStepsRaw's doc comment).
	steps, _, err := buildARTTechniquesSteps(techniques, artStore, platform)
	return steps, err
}

func buildARTTechniquesSteps(techniques []string, artStore *ARTStore, platform string) ([]ScenarioStep, []CalderaSkippedAbility, error) {
	if platform == "" {
		platform = "windows"
	}
	// Dedup by normalized technique ID before expanding. Callers (operator-
	// selected subsets, campaigns, generated packs) don't all guarantee a
	// unique list, and expanding the same technique's full atomic-test set
	// twice would dispatch identical steps twice in one run.
	var steps []ScenarioStep
	var skipped []CalderaSkippedAbility
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
			skipped = append(skipped, CalderaSkippedAbility{
				Framework: "art", TechniqueID: id,
				Reason: "no " + platform + " ART atomic available for this technique",
			})
			continue
		}
		for _, st := range s {
			steps = append(steps, artStore.materialize(st))
		}
	}
	if len(steps) == 0 {
		return nil, skipped, fmt.Errorf("ART: no %s steps found for any of the %d requested techniques", platform, len(techniques))
	}
	return steps, skipped, nil
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
// for every ability that has a Windows (psh/powershell/cmd) executor. Any
// ability that fails to resolve or has no Windows-compatible executor is
// reported in the returned skipped list rather than silently dropped --
// mirrors buildCalderaAbilitiesSteps, which had the same "declared vs
// found" gap and was already fixed.
func buildCalderaAdversarySteps(adversaryID, calderaURL, apiKey string) ([]ScenarioStep, []CalderaSkippedAbility, error) {
	if !safeID.MatchString(adversaryID) {
		return nil, nil, fmt.Errorf("invalid adversary ID %q: must be alphanumeric/hyphen/underscore", adversaryID)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	base := strings.TrimRight(calderaURL, "/")

	req, _ := http.NewRequest("GET", base+"/api/v2/adversaries/"+adversaryID, nil)
	if apiKey != "" {
		req.Header.Set("KEY", apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch adversary: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("fetch adversary: HTTP %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var adversary calderaAdversary
	if err := json.Unmarshal(body, &adversary); err != nil {
		return nil, nil, fmt.Errorf("parse adversary: %w", err)
	}
	if len(adversary.AtomicOrdering) == 0 {
		return nil, nil, fmt.Errorf("adversary %s has no abilities in atomic_ordering", adversaryID)
	}

	var steps []ScenarioStep
	var skipped []CalderaSkippedAbility
	for _, abilityID := range adversary.AtomicOrdering {
		ab, err := fetchCalderaAbilityFull(client, base, apiKey, abilityID)
		if err != nil {
			log.Printf("[caldera] adversary %s: ability %s not found — skipped (%v)", adversaryID, abilityID, err)
			skipped = append(skipped, CalderaSkippedAbility{
				Framework: "caldera", AbilityID: abilityID, Reason: "not found in Caldera library",
			})
			continue
		}
		cmd := pickExecutorCommand(ab.Executors, "psh")
		if cmd == "" {
			log.Printf("[caldera] adversary %s: ability %s (%q) has no Windows-compatible executor — skipped", adversaryID, abilityID, ab.Name)
			techniqueID := ab.TechniqueID
			if techniqueID == "" {
				techniqueID = ab.Tactic
			}
			skipped = append(skipped, CalderaSkippedAbility{
				Framework: "caldera", AbilityID: abilityID, Name: ab.Name, TechniqueID: techniqueID,
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
		return nil, skipped, fmt.Errorf("adversary %s yielded no executable steps for Windows platform", adversaryID)
	}
	return steps, skipped, nil
}

// CalderaSkippedAbility explains why a configured caldera_abilities,
// caldera_adversary_id, or art_techniques entry never became a dispatched
// step. Surfaced up through BuildSteps so the operator can see WHICH ids/
// techniques were dropped and WHY, instead of just noticing the run's total
// came in lower than the scenario's configured count. Despite the name
// (kept to avoid an unrelated rename across every existing caller), this is
// shared by both Caldera and ART shorthand modes — Framework disambiguates
// which one a given entry came from for the message synthesized from it.
type CalderaSkippedAbility struct {
	Framework   string // "caldera" or "art" — which shorthand mode produced this skip
	AbilityID   string // as configured in the scenario YAML; empty for an "art" skip
	Name        string // ability name, only known if the id resolved; empty for an "art" skip
	TechniqueID string // only known if the id resolved (caldera) or always set (art)
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
			skipped = append(skipped, CalderaSkippedAbility{Framework: "caldera", AbilityID: id, Reason: "not found in Caldera library"})
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
				Framework: "caldera", AbilityID: id, Name: ab.Name, TechniqueID: techniqueID,
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
