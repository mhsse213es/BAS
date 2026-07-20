package scenario

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/audspect/bas/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"
)

type artAtomicFile struct {
	AttackTechnique string          `yaml:"attack_technique"`
	DisplayName     string          `yaml:"display_name"`
	AtomicTests     []artAtomicTest `yaml:"atomic_tests"`
}

type artAtomicTest struct {
	Name               string                 `yaml:"name"`
	SupportedPlatforms []string               `yaml:"supported_platforms"`
	InputArguments     map[string]artInputArg `yaml:"input_arguments"`
	Executor           artExecutor            `yaml:"executor"`
}

type artInputArg struct {
	Default string `yaml:"default"`
}

type artExecutor struct {
	Name              string `yaml:"name"`
	Command           string `yaml:"command"`
	CleanupCommand    string `yaml:"cleanup_command"`
	ElevationRequired bool   `yaml:"elevation_required"`
}

// mapARTElevation translates Atomic Red Team's raw executor.elevation_required
// boolean into this platform's framework-agnostic privilege tier (PrivSpec).
// This is the ART-specific half of the import normalization boundary —
// nothing downstream of normalizeAtomic ever sees "elevation_required" again,
// only PrivSpec. A future importer for a different framework (a different raw
// signal shape — required_integrity, requires_sudo, run_as, ...) gets its own
// mapXyzElevation function that converges on the same PrivSpec, keeping the
// rest of the engine source-agnostic.
func mapARTElevation(required bool) PrivSpec {
	if required {
		return PrivSpec{Minimum: "admin"}
	}
	return PrivSpec{Minimum: "user"}
}

// ARTStore holds pre-loaded ART atomic steps keyed by ATT&CK technique ID.
// All steps are resolved at load time — no network access at run time.
type ARTStore struct {
	mu       sync.RWMutex
	steps    map[string][]ScenarioStep
	payloads *PayloadStore // server-side external-payload store (may be nil)
}

// NewARTStore loads all T*.yaml files from dir and returns a ready-to-use store.
// payloads is the server-side external-payload store used to ship binaries to
// the agent at dispatch (may be nil — then payload atomics are skipped).
func NewARTStore(dir string, payloads *PayloadStore) (*ARTStore, error) {
	s := &ARTStore{steps: make(map[string][]ScenarioStep), payloads: payloads}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("ART dir %q: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		techniqueID, steps, err := parseARTFile(filepath.Join(dir, e.Name()))
		if err != nil {
			log.Printf("[ART] skip %s: %v", e.Name(), err)
			continue
		}
		if len(steps) > 0 {
			s.steps[techniqueID] = steps
		}
	}
	return s, nil
}

// NewARTStoreFromDB builds the store from the art_atomic_tests runtime table.
// Rows are already parsed and execution-ready (commands resolved, payload-folder
// references rewritten), so no YAML is parsed at boot. This is the runtime
// constructor; NewARTStore (disk parse) is retained for tests and the seed path.
func NewARTStoreFromDB(ctx context.Context, pool *pgxpool.Pool, payloads *PayloadStore) (*ARTStore, error) {
	s := &ARTStore{steps: make(map[string][]ScenarioStep), payloads: payloads}
	rows, err := pool.Query(ctx,
		`SELECT technique_id, name, executor, command, cleanup, timeout_sec, required_payloads, platform, requires_priv
		   FROM art_atomic_tests
		  ORDER BY technique_id, test_index`)
	if err != nil {
		return nil, fmt.Errorf("load atomic tests: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tech, name, executor, command, cleanup, platform, requiresPriv string
		var timeout int
		var required []string
		if err := rows.Scan(&tech, &name, &executor, &command, &cleanup, &timeout, &required, &platform, &requiresPriv); err != nil {
			return nil, err
		}
		tech = strings.ToUpper(tech)
		if timeout <= 0 {
			timeout = 120
		}
		if platform == "" {
			platform = "windows"
		}
		s.steps[tech] = append(s.steps[tech], ScenarioStep{
			TaskID:           TaskID(tech, name),
			TechniqueID:      tech,
			Name:             name,
			Framework:        "art",
			Platform:         platform,
			Executor:         executor,
			Command:          command,
			TimeoutSec:       timeout,
			Cleanup:          cleanup,
			RequiresPriv:     requiresPriv,
			requiredPayloads: required,
		})
	}
	return s, rows.Err()
}

// Reload re-reads atomic tests from the DB and swaps them in under the write
// lock, then reloads the underlying payload store. Used by the admin reseed
// endpoint so a dropped content pack takes effect without a restart.
func (s *ARTStore) Reload(ctx context.Context, pool *pgxpool.Pool) error {
	fresh, err := NewARTStoreFromDB(ctx, pool, s.payloads)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.steps = fresh.steps
	s.mu.Unlock()
	if s.payloads != nil {
		if err := s.payloads.Reload(ctx, pool); err != nil {
			return err
		}
	}
	return nil
}

// Count returns the number of techniques with at least one Windows step.
func (s *ARTStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.steps)
}

// GetSteps returns Windows ScenarioSteps for a given technique ID (backward compat).
func (s *ARTStore) GetSteps(techniqueID string) []ScenarioStep {
	return s.GetStepsByPlatform(techniqueID, "windows")
}

// GetStepsByPlatform returns ScenarioSteps for a given technique ID and platform.
// platform should be "windows", "linux", or "darwin". Empty string → "windows".
func (s *ARTStore) GetStepsByPlatform(techniqueID, platform string) []ScenarioStep {
	if platform == "" {
		platform = "windows"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := s.steps[strings.ToUpper(techniqueID)]
	if len(all) == 0 {
		return nil
	}
	var out []ScenarioStep
	for _, st := range all {
		p := st.Platform
		if p == "" {
			p = "windows" // legacy steps with no platform tag default to windows
		}
		if strings.EqualFold(p, platform) {
			out = append(out, st)
		}
	}
	return out
}

// ListTechniquesByPlatform returns technique IDs that have at least one step for
// the given platform, sorted. Used by full-platform sweep builds.
func (s *ARTStore) ListTechniquesByPlatform(platform string) []string {
	if platform == "" {
		platform = "windows"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for id, steps := range s.steps {
		for _, st := range steps {
			p := st.Platform
			if p == "" {
				p = "windows"
			}
			if strings.EqualFold(p, platform) {
				out = append(out, id)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// ListTechniques returns all technique IDs that have at least one Windows step, sorted.
func (s *ARTStore) ListTechniques() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.steps))
	for k := range s.steps {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TechniqueMeta is a lightweight catalog entry for the dashboard technique picker,
// real-time live-run timeline enrichment, and card count.
type TechniqueMeta struct {
	ID     string `json:"id"`     // ATT&CK technique ID, e.g. T1003.001
	Name   string `json:"name"`   // representative atomic name (first Windows test)
	Tests  int    `json:"tests"`  // number of Windows atomic tests for this technique
	Tactic string `json:"tactic"` // ATT&CK tactic, e.g. "credential-access"
}

// ListTechniqueMeta returns one catalog entry per technique that has at least one
// Windows step, sorted by technique ID. Drives the live count shown on sweep cards
// and the selectable technique picker.
func (s *ARTStore) ListTechniqueMeta() []TechniqueMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TechniqueMeta, 0, len(s.steps))
	for id, steps := range s.steps {
		name := ""
		if len(steps) > 0 {
			name = steps[0].Name
		}
		out = append(out, TechniqueMeta{ID: id, Name: name, Tests: len(steps), Tactic: models.LookupTactic(id)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// UnknownTechniques returns the subset of the given technique IDs that are NOT
// present in the store (case-insensitive). An empty result means all are valid.
// Used to validate an operator-selected technique subset before dispatch.
func (s *ARTStore) UnknownTechniques(ids []string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var missing []string
	for _, id := range ids {
		if _, ok := s.steps[strings.ToUpper(strings.TrimSpace(id))]; !ok {
			missing = append(missing, id)
		}
	}
	return missing
}

func parseARTFile(path string) (string, []ScenarioStep, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	var f artAtomicFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return "", nil, err
	}
	techniqueID := strings.ToUpper(strings.TrimSpace(f.AttackTechnique))
	if techniqueID == "" {
		return "", nil, fmt.Errorf("missing attack_technique")
	}

	var steps []ScenarioStep

	// ── Windows atomics ──────────────────────────────────────────────────────
	for i, test := range f.AtomicTests {
		if !artIsWindows(test.SupportedPlatforms) {
			continue
		}
		execName := strings.ToLower(test.Executor.Name)
		var executor string
		switch execName {
		case "powershell":
			executor = "powershell"
		case "command_prompt":
			executor = "cmd"
		default:
			continue
		}
		cmd := artResolveArgs(test.Executor.Command, test.InputArguments)
		if cmd == "" {
			continue
		}
		cleanup := artResolveArgs(test.Executor.CleanupCommand, test.InputArguments)
		cmd, required := artResolvePayloads(cmd, executor)
		cleanup, _ = artResolvePayloads(cleanup, executor)
		name := fmt.Sprintf("%s - Test %d: %s", techniqueID, i+1, test.Name)
		steps = append(steps, ScenarioStep{
			TaskID: TaskID(techniqueID, name), TechniqueID: techniqueID, Name: name,
			Framework: "art", Platform: "windows", Executor: executor,
			Command: cmd, TimeoutSec: 120, Cleanup: cleanup, requiredPayloads: required,
		})
	}

	// ── Linux / macOS atomics ────────────────────────────────────────────────
	for i, test := range f.AtomicTests {
		platform := artUnixPlatform(test.SupportedPlatforms)
		if platform == "" {
			continue
		}
		execName := strings.ToLower(test.Executor.Name)
		switch execName {
		case "bash", "sh", "zsh", "fish":
		default:
			continue // skip manual/powershell on unix
		}
		cmd := artResolveArgs(test.Executor.Command, test.InputArguments)
		if cmd == "" {
			continue
		}
		cleanup := artResolveArgs(test.Executor.CleanupCommand, test.InputArguments)
		cmd, required := artResolvePayloadsUnix(cmd)
		cleanup, _ = artResolvePayloadsUnix(cleanup)
		name := fmt.Sprintf("%s - Test %d: %s", techniqueID, i+1, test.Name)
		steps = append(steps, ScenarioStep{
			TaskID: TaskID(techniqueID, name), TechniqueID: techniqueID, Name: name,
			Framework: "art", Platform: platform, Executor: "bash",
			Command: cmd, TimeoutSec: 120, Cleanup: cleanup, requiredPayloads: required,
		})
	}

	return techniqueID, steps, nil
}

func artIsWindows(platforms []string) bool {
	for _, p := range platforms {
		if strings.EqualFold(p, "windows") {
			return true
		}
	}
	return false
}

// artUnixPlatform returns "linux" or "darwin" if the test supports either,
// preferring the most specific match. Returns "" for Windows-only tests.
func artUnixPlatform(platforms []string) string {
	var hasLinux, hasDarwin bool
	for _, p := range platforms {
		switch strings.ToLower(p) {
		case "linux":
			hasLinux = true
		case "macos", "darwin":
			hasDarwin = true
		}
	}
	if hasLinux && hasDarwin {
		return "linux" // store under linux; darwin dispatch will also match via cross-platform logic
	}
	if hasLinux {
		return "linux"
	}
	if hasDarwin {
		return "darwin"
	}
	return ""
}

func artResolveArgs(cmd string, args map[string]artInputArg) string {
	if cmd == "" {
		return ""
	}
	for name, arg := range args {
		def := arg.Default
		if def == "" {
			def = `$env:TEMP\bas-placeholder-` + name
		}
		cmd = strings.ReplaceAll(cmd, "#{"+name+"}", def)
	}
	return cmd
}

// artPayloadFileRe matches a file reference (with extension) rooted at the ART
// PathToAtomicsFolder variable in any of its forms (#{PathToAtomicsFolder},
// $PathToAtomicsFolder, or bare PathToAtomicsFolder).
var artPayloadFileRe = regexp.MustCompile(
	`(?i)(?:#\{PathToAtomicsFolder\}|\$PathToAtomicsFolder|PathToAtomicsFolder)[\\/][^\s"'<>|;,)]*\.[A-Za-z0-9]{1,6}`)

// artPathRootRe matches any remaining PathToAtomicsFolder root token (used for
// directory references after file references have been rewritten).
var artPathRootRe = regexp.MustCompile(`(?i)#\{PathToAtomicsFolder\}|\$PathToAtomicsFolder|PathToAtomicsFolder`)

// artResolvePayloads rewrites ART payload-folder references to the agent's
// staging directory and returns the rewritten command plus the set of external
// payload basenames the command requires. Executor selects the env-var syntax.
func artResolvePayloads(cmd, executor string) (string, []string) {
	if cmd == "" {
		return "", nil
	}
	envRef := `$env:BAS_PAYLOAD_DIR`
	if executor == "cmd" {
		envRef = `%BAS_PAYLOAD_DIR%`
	}

	seen := make(map[string]bool)
	var required []string
	cmd = artPayloadFileRe.ReplaceAllStringFunc(cmd, func(match string) string {
		base := payloadBasename(match)
		if base == "" {
			return match
		}
		if !seen[strings.ToLower(base)] {
			seen[strings.ToLower(base)] = true
			required = append(required, base)
		}
		return envRef + `\` + base
	})

	// Any leftover directory-style references → point at the staging dir root.
	// Use a func replacement so "$" in $env:... is emitted literally (a plain
	// replacement string would treat $ as a regexp group reference).
	cmd = artPathRootRe.ReplaceAllStringFunc(cmd, func(string) string { return envRef })
	return cmd, required
}

// artResolvePayloadsUnix rewrites ART PathToAtomicsFolder references for bash/sh
// execution on Linux/macOS: uses $BAS_PAYLOAD_DIR with forward-slash separator.
func artResolvePayloadsUnix(cmd string) (string, []string) {
	if cmd == "" {
		return "", nil
	}
	const envRef = `$BAS_PAYLOAD_DIR`
	seen := make(map[string]bool)
	var required []string
	cmd = artPayloadFileRe.ReplaceAllStringFunc(cmd, func(match string) string {
		base := payloadBasename(match)
		if base == "" {
			return match
		}
		if !seen[strings.ToLower(base)] {
			seen[strings.ToLower(base)] = true
			required = append(required, base)
		}
		return envRef + "/" + base
	})
	cmd = artPathRootRe.ReplaceAllStringFunc(cmd, func(string) string { return envRef })
	return cmd, required
}

// payloadBasename extracts the final path segment (the filename) from a matched
// payload path, ignoring "." and ".." segments and either slash style.
func payloadBasename(path string) string {
	norm := strings.ReplaceAll(path, "/", `\`)
	parts := strings.Split(norm, `\`)
	for i := len(parts) - 1; i >= 0; i-- {
		seg := strings.TrimSpace(parts[i])
		if seg != "" && seg != "." && seg != ".." {
			return seg
		}
	}
	return ""
}

// materialize prepares an ART step for dispatch: it ships every required
// external payload from the server store into the step's Payloads, or — if any
// payload is missing — replaces the command with a clean SKIP so the result is
// recorded as skipped rather than failing with "not recognized".
func (s *ARTStore) materialize(step ScenarioStep) ScenarioStep {
	if len(step.requiredPayloads) == 0 {
		return step
	}
	var missing []string
	var staged []Payload
	for _, base := range step.requiredPayloads {
		path, ok := s.payloads.Path(base)
		if !ok {
			missing = append(missing, base)
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			missing = append(missing, base)
			continue
		}
		staged = append(staged, Payload{
			Name:    base,
			Content: base64.StdEncoding.EncodeToString(data),
		})
	}
	if len(missing) > 0 {
		step.Payloads = nil
		step.Cleanup = ""
		step.Command = skipCommand(step.Executor,
			"requires external payload(s) not available on server: "+strings.Join(missing, ", ")+
				" — drop them in ART_PAYLOAD_DIR to enable this test")
		return step
	}
	step.Payloads = append(step.Payloads, staged...)
	return step
}

// skipCommand returns an executor-appropriate command that emits a SKIP marker
// the interpreter records as ResultSkipped.
func skipCommand(executor, reason string) string {
	if executor == "cmd" {
		return "echo SKIP: " + reason
	}
	return `Write-Output "SKIP: ` + strings.ReplaceAll(reason, `"`, `'`) + `"`
}
