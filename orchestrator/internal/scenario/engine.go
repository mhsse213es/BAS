package scenario

import (
	"fmt"
	"io/fs"
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
// Safe to call multiple times — reloads on each call.
func (e *Engine) Load() error {
	e.scenarios = make(map[string]*Scenario)
	return filepath.WalkDir(e.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		var s Scenario
		if err := yaml.Unmarshal(b, &s); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if s.ID == "" {
			return fmt.Errorf("%s: scenario missing required field 'id'", path)
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
