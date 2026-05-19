package scenario

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type artAtomicFile struct {
	AttackTechnique string         `yaml:"attack_technique"`
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
	mu    sync.RWMutex
	steps map[string][]ScenarioStep
}

// NewARTStore loads all T*.yaml files from dir and returns a ready-to-use store.
func NewARTStore(dir string) (*ARTStore, error) {
	s := &ARTStore{steps: make(map[string][]ScenarioStep)}
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
		name := fmt.Sprintf("%s - Test %d: %s", techniqueID, i+1, test.Name)
		steps = append(steps, ScenarioStep{
			TaskID:      TaskID(techniqueID, name),
			TechniqueID: techniqueID,
			Name:        name,
			Executor:    executor,
			Command:     cmd,
			TimeoutSec:  120,
			Cleanup:     cleanup,
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
	cmd = strings.ReplaceAll(cmd, "#{PathToAtomicsFolder}", `$env:TEMP\bas-art`)
	for name, arg := range args {
		def := arg.Default
		if def == "" {
			def = `$env:TEMP\bas-placeholder-` + name
		}
		cmd = strings.ReplaceAll(cmd, "#{"+name+"}", def)
	}
	return cmd
}
