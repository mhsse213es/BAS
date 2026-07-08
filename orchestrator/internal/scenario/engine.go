package scenario

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/integrity"
)

// idPattern restricts custom scenario IDs to a filesystem-safe slug so a user
// can never write outside scenarios/custom/ via a crafted ID.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`)

// profilesSubdir holds Detection Validation profiles under the scenarios root.
// It is walked by the profile loader, and explicitly skipped by the scenario
// loader (profiles are not scenarios and would fail scenario parsing).
const profilesSubdir = "detection-profiles"

// Engine loads and manages scenario definitions from YAML files.
type Engine struct {
	dir       string
	scenarios map[string]*Scenario
	profiles  map[string]*DetectionProfile
}

// NewEngine creates an Engine that reads scenarios from dir.
func NewEngine(dir string) *Engine {
	return &Engine{
		dir:       dir,
		scenarios: make(map[string]*Scenario),
		profiles:  make(map[string]*DetectionProfile),
	}
}

// Load reads all *.yaml files in the scenarios directory.
// Individual file errors are logged and skipped — a bad file never blocks the rest.
// Safe to call multiple times — reloads on each call.
func (e *Engine) Load() error {
	e.scenarios = make(map[string]*Scenario)
	// Load Detection Validation profiles first so scenario resolution can
	// reference them. Profile errors are logged, never fatal.
	e.loadProfiles()
	return filepath.WalkDir(e.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err // directory-level error — abort
		}
		if d.IsDir() {
			// Detection profiles live under scenarios/detection-profiles/ but are
			// not scenarios — skip that whole subtree in the scenario loader.
			if d.Name() == profilesSubdir {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".yaml" {
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
		s.Source = e.sourceForPath(path)

		// Signature verification: only builtin (vendor-shipped) scenarios must be
		// signed. Custom and intel scenarios are operator/connector-created and
		// intentionally have no signature — they are always accepted.
		if s.Source == "builtin" {
			if err := integrity.VerifyScenarioFile(path); err != nil {
				log.Printf("[!] TAMPER ALERT: builtin scenario %s failed signature verification: %v — refusing to load", path, err)
				return nil // skip — do not add tampered scenario to the map
			}
		}

		e.scenarios[s.ID] = &s
		return nil
	})
}

// sourceForPath classifies a scenario file by which sub-folder it lives in,
// relative to the scenarios root: "custom", "intel", or "builtin".
func (e *Engine) sourceForPath(path string) string {
	rel, err := filepath.Rel(e.dir, path)
	if err != nil {
		return "builtin"
	}
	switch {
	case strings.HasPrefix(rel, "custom"+string(os.PathSeparator)):
		return "custom"
	case strings.HasPrefix(rel, "intel"+string(os.PathSeparator)):
		return "intel"
	default:
		return "builtin"
	}
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

// ParseYAML parses a single scenario from raw YAML bytes (e.g. an uploaded file)
// and validates it. It does not write anything — pass the result to Save.
func ParseYAML(b []byte) (*Scenario, error) {
	var s Scenario
	if err := yaml.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Validate checks that a scenario is well-formed enough to save and run.
// Returns a human-readable error describing the first problem found.
func (s *Scenario) Validate() error {
	if !idPattern.MatchString(s.ID) {
		return fmt.Errorf("id must be 2-64 chars, lowercase letters/digits/hyphens, and start with a letter or digit")
	}
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("name is required")
	}
	// At least one execution mode must be set.
	hasMode := s.LocalCheck || s.CalderaAllWindows || s.ARTAllWindows ||
		len(s.CalderaAbilities) > 0 || s.CalderaAdversaryID != "" ||
		len(s.ARTTechniques) > 0 || len(s.Steps) > 0
	if !hasMode {
		return fmt.Errorf("scenario has no execution mode: add steps, ART techniques, Caldera abilities, or set local_check")
	}
	// Custom steps must each name a technique.
	for i, st := range s.Steps {
		if strings.TrimSpace(st.TechniqueID) == "" {
			return fmt.Errorf("step %d (%q) is missing a technique_id", i+1, st.Name)
		}
	}
	return nil
}

// Save validates a scenario and writes it as YAML into scenarios/custom/<id>.yaml,
// then updates the in-memory map. It refuses to overwrite a builtin or intel file
// (those live outside custom/) so shipped content can never be clobbered.
func (e *Engine) Save(s *Scenario) error {
	if err := s.Validate(); err != nil {
		return err
	}
	// If a scenario with this ID already exists, it must be a custom one.
	if existing, ok := e.scenarios[s.ID]; ok && existing.Source != "custom" {
		return fmt.Errorf("scenario %q is %s and cannot be overwritten — clone it to a new ID instead", s.ID, existing.Source)
	}

	customDir := filepath.Join(e.dir, "custom")
	if err := os.MkdirAll(customDir, 0o755); err != nil {
		return fmt.Errorf("create custom dir: %w", err)
	}

	s.Source = "" // never persist the runtime-only field
	b, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal scenario: %w", err)
	}

	dest := filepath.Join(customDir, s.ID+".yaml")
	if err := os.WriteFile(dest, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}

	s.Source = "custom"
	e.scenarios[s.ID] = s
	return nil
}

// Delete removes a custom or intel scenario from memory and deletes its YAML file.
// Builtin (shipped) scenarios cannot be deleted. Returns an error if the file
// cannot be found or removed.
func (e *Engine) Delete(id string) error {
	sc, ok := e.scenarios[id]
	if !ok {
		return fmt.Errorf("scenario %q not found", id)
	}
	if sc.Source == "builtin" {
		return fmt.Errorf("scenario %q is a built-in and cannot be deleted", id)
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
