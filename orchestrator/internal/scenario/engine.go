package scenario

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// Engine loads and manages scenario definitions from YAML files.
type Engine struct {
	dir       string
	scenarios map[string]*Scenario
}

// NewEngine creates an Engine that reads scenarios from dir.
func NewEngine(dir string) *Engine {
	return &Engine{dir: dir, scenarios: make(map[string]*Scenario)}
}

// Load reads all *.yaml files in the scenarios directory.
// Individual file errors are logged and skipped — a bad file never blocks the rest.
// Safe to call multiple times — reloads on each call.
func (e *Engine) Load() error {
	e.scenarios = make(map[string]*Scenario)
	return filepath.WalkDir(e.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err // directory-level error — abort
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[!] scenario: read %s: %v — skipping", path, err)
			return nil
		}
		var s Scenario
		if err := yaml.Unmarshal(b, &s); err != nil {
			log.Printf("[!] scenario: parse %s: %v — skipping", path, err)
			return nil
		}
		if s.ID == "" {
			log.Printf("[!] scenario: %s missing required field 'id' — skipping", path)
			return nil
		}
		e.scenarios[s.ID] = &s
		return nil
	})
}

// List returns all loaded scenarios sorted by ID.
func (e *Engine) List() []*Scenario {
	out := make([]*Scenario, 0, len(e.scenarios))
	for _, s := range e.scenarios {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns a scenario by ID.
func (e *Engine) Get(id string) (*Scenario, bool) {
	s, ok := e.scenarios[id]
	return s, ok
}

// Count returns the number of loaded scenarios.
func (e *Engine) Count() int {
	return len(e.scenarios)
}

// Delete removes an intel scenario from memory and deletes its YAML file.
// Returns an error if the file cannot be found or removed.
func (e *Engine) Delete(id string) error {
	sc, ok := e.scenarios[id]
	if !ok {
		return fmt.Errorf("scenario %q not found", id)
	}

	// Find the file on disk by re-scanning for the matching ID
	var found string
	filepath.WalkDir(e.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var s Scenario
		if yaml.Unmarshal(b, &s) == nil && s.ID == sc.ID {
			found = path
		}
		return nil
	})

	if found == "" {
		return fmt.Errorf("YAML file for scenario %q not found on disk", id)
	}
	if err := os.Remove(found); err != nil {
		return fmt.Errorf("remove %s: %w", found, err)
	}
	delete(e.scenarios, id)
	return nil
}
