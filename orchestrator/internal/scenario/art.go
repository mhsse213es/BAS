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
	Name           string `yaml:"name"`
	Command        string `yaml:"command"`
	CleanupCommand string `yaml:"cleanup_command"`
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
		`SELECT technique_id, name, executor, command, cleanup, timeout_sec, required_payloads
		   FROM art_atomic_tests
		  ORDER BY technique_id, test_index`)
	if err != nil {
		return nil, fmt.Errorf("load atomic tests: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tech, name, executor, command, cleanup string
		var timeout int
		var required []string
		if err := rows.Scan(&tech, &name, &executor, &command, &cleanup, &timeout, &required); err != nil {
			return nil, err
		}
		tech = strings.ToUpper(tech)
		if timeout <= 0 {
			timeout = 120
		}
		s.steps[tech] = append(s.steps[tech], ScenarioStep{
			TaskID:           TaskID(tech, name),
			TechniqueID:      tech,
			Name:             name,
			Framework:        "art",
			Executor:         executor,
			Command:          command,
			TimeoutSec:       timeout,
			Cleanup:          cleanup,
			requiredPayloads: required,
		})
	}
	return s, rows.Err()
}

// Count returns the number of techniques with at least one Windows step.
func (s *ARTStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.steps)
}

// GetSteps returns all Windows ScenarioSteps for a given technique ID.
func (s *ARTStore) GetSteps(techniqueID string) []ScenarioStep {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.steps[strings.ToUpper(techniqueID)]
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
			continue // skip bash/sh/manual
		}

		cmd := artResolveArgs(test.Executor.Command, test.InputArguments)
		if cmd == "" {
			continue
		}
		cleanup := artResolveArgs(test.Executor.CleanupCommand, test.InputArguments)

		// Rewrite ART payload-folder references to the agent's staging dir
		// ($env:BAS_PAYLOAD_DIR / %BAS_PAYLOAD_DIR%) and record which external
		// payload files the command needs so they can be shipped at dispatch.
		cmd, required := artResolvePayloads(cmd, executor)
		cleanup, _ = artResolvePayloads(cleanup, executor)

		name := fmt.Sprintf("%s - Test %d: %s", techniqueID, i+1, test.Name)
		steps = append(steps, ScenarioStep{
			TaskID:           TaskID(techniqueID, name),
			TechniqueID:      techniqueID,
			Name:             name,
			Framework:        "art",
			Executor:         executor,
			Command:          cmd,
			TimeoutSec:       120,
			Cleanup:          cleanup,
			requiredPayloads: required,
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
