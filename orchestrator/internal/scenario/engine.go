package scenario

import (
	"context"
	"errors"
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
	// registry is the TCF Content Registry. nil => nothing is executable
	// (ResolveExecutable fails closed); the disk map still serves authoring.
	registry ContentRegistry
	verifier integrity.Verifier
}

// NewEngine creates an Engine that reads scenarios from dir.
func NewEngine(dir string) *Engine {
	return &Engine{
		dir:       dir,
		scenarios: make(map[string]*Scenario),
		profiles:  make(map[string]*DetectionProfile),
		verifier:  integrity.CompiledVerifier{},
	}
}

// AttachRegistry wires the TCF Content Registry into the engine.
func (e *Engine) AttachRegistry(r ContentRegistry) { e.registry = r }

// Registry returns the attached content registry, or nil.
func (e *Engine) Registry() ContentRegistry { return e.registry }

// SetVerifier overrides the builtin-signature verifier (tests; rotated keys).
func (e *Engine) SetVerifier(v integrity.Verifier) { e.verifier = v }

// ResolveExecutable is the only way callers may obtain a scenario to run.
func (e *Engine) ResolveExecutable(ctx context.Context, id string) (ExecutableVersion, error) {
	if e.registry == nil {
		return ExecutableVersion{}, ErrNoRegistry
	}
	return e.registry.ResolveExecutable(ctx, id)
}

type loadedFile struct {
	path   string
	source string
	bytes  []byte
	sc     *Scenario
}

var sourceRank = map[string]int{"builtin": 0, "custom": 1, "intel": 2}

// Load reads all *.yaml files in the scenarios directory. With a registry
// attached, every file is handed to intake in builtin -> custom -> intel
// order (so first registration can never let a custom file claim a builtin
// identity); a refused or errored file is left out of the map. A duplicate
// id always keeps the first (higher-precedence) file in the map.
// Individual file errors are logged and skipped — a bad file never blocks the rest.
// Safe to call multiple times — reloads on each call.
func (e *Engine) Load() error {
	e.scenarios = make(map[string]*Scenario)
	// Load Detection Validation profiles first so scenario resolution can
	// reference them. Profile errors are logged, never fatal.
	e.loadProfiles()
	var files []loadedFile
	err := filepath.WalkDir(e.dir, func(path string, d fs.DirEntry, err error) error {
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
		files = append(files, loadedFile{path: path, source: s.Source, bytes: b, sc: &s})
		return nil
	})
	if err != nil {
		return err
	}
	sort.SliceStable(files, func(i, j int) bool { return sourceRank[files[i].source] < sourceRank[files[j].source] })

	ctx := context.Background()
	for _, f := range files {
		// Signature verification: only builtin (vendor-shipped) scenarios must be
		// signed. Custom and intel scenarios are operator/connector-created and
		// intentionally have no signature.
		var sig []byte
		var verified bool
		if f.source == "builtin" {
			s, ok, verr := integrity.ReadBuiltinSignature(e.verifier, f.path, f.bytes)
			if verr != nil {
				log.Printf("[!] TAMPER ALERT: builtin scenario %s failed signature verification: %v — refusing to load", f.path, verr)
				if e.registry != nil {
					e.registry.NoteRefusal(f.path, f.sc.ID, verr.Error())
				}
				continue // do not add tampered scenario to the map
			}
			sig, verified = s, ok
		}
		if e.registry != nil {
			d, ierr := e.registry.Intake(ctx, IntakeFile{Path: f.path, Source: f.source, Artifact: f.bytes,
				Signature: sig, SignatureVerified: verified})
			if ierr != nil {
				log.Printf("[!] content registry intake %s: %v — not loaded", f.path, ierr)
				continue
			}
			if !d.Accepted {
				log.Printf("[!] content registry refused %s: %s", f.path, d.Reason)
				continue
			}
		}
		// First wins, with or without a registry: the higher-precedence file
		// already in the map keeps the slot even if the registry accepted
		// the later file (e.g. custom vs intel, both LOCAL).
		if _, dup := e.scenarios[f.sc.ID]; dup {
			log.Printf("[!] scenario: duplicate id %s at %s — keeping the first (higher-precedence) file", f.sc.ID, f.path)
			if e.registry != nil {
				e.registry.NoteRefusal(f.path, f.sc.ID, "duplicate id; higher-precedence file wins")
			}
			continue
		}
		e.scenarios[f.sc.ID] = f.sc
	}
	return nil
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

// SaveAs validates a scenario and writes it as YAML into
// scenarios/custom/<id>.yaml, then updates the in-memory map. It refuses to
// overwrite a builtin or intel file (those live outside custom/) so shipped
// content can never be clobbered. With a registry attached it registers
// exactly the written bytes as an operator-approved PUBLISHED_LOCAL version
// (spec §5.1 "UI save path"); if registration fails the previous file is
// restored and the map is unchanged.
func (e *Engine) SaveAs(ctx context.Context, s *Scenario, actor string) error {
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

	origSource := s.Source
	s.Source = "" // never persist the runtime-only field
	b, err := yaml.Marshal(s)
	if err != nil {
		s.Source = origSource
		return fmt.Errorf("marshal scenario: %w", err)
	}

	dest := filepath.Join(customDir, s.ID+".yaml")
	// With a registry, a failed registration must restore the previous
	// file, so read it first. Only "does not exist" means there is nothing
	// to restore; any other read failure refuses the save before writing.
	var prev []byte
	hadPrev := false
	if e.registry != nil {
		p, rerr := os.ReadFile(dest)
		switch {
		case rerr == nil:
			prev, hadPrev = p, true
		case !errors.Is(rerr, fs.ErrNotExist):
			s.Source = origSource
			return fmt.Errorf("read existing %s: %w", dest, rerr)
		}
	}
	if err := os.WriteFile(dest, b, 0o644); err != nil {
		s.Source = origSource
		return fmt.Errorf("write %s: %w", dest, err)
	}
	if e.registry != nil {
		if err := e.registry.RegisterLocalApproved(ctx, s.ID, b, actor); err != nil {
			s.Source = origSource
			var restoreErr error
			if hadPrev {
				restoreErr = os.WriteFile(dest, prev, 0o644)
			} else {
				restoreErr = os.Remove(dest)
			}
			if restoreErr != nil {
				log.Printf("[!] scenario: restore %s after content registry failure: %v", dest, restoreErr)
				restoreErr = fmt.Errorf("restore %s: %w", dest, restoreErr)
			}
			return errors.Join(fmt.Errorf("content registry: %w", err), restoreErr)
		}
	}

	s.Source = "custom"
	e.scenarios[s.ID] = s
	return nil
}

// DeleteAs removes a custom scenario from memory and deletes its YAML file.
// Builtin (shipped) and intel (threat-intel-generated) scenarios cannot be
// deleted, by anyone, through any caller -- enforced here rather than only
// at the API layer so no future handler can accidentally reopen the path.
// With a registry attached, the scenario's executable versions are retired
// before the file is touched; a failed retirement leaves everything in place.
// Returns an error if the file cannot be found or removed.
func (e *Engine) DeleteAs(ctx context.Context, id, actor string) error {
	sc, ok := e.scenarios[id]
	if !ok {
		return fmt.Errorf("scenario %q not found", id)
	}
	if sc.Source == "builtin" {
		return fmt.Errorf("scenario %q is a built-in and cannot be deleted", id)
	}
	if sc.Source == "intel" {
		return fmt.Errorf("scenario %q is auto-generated from threat intel and cannot be deleted", id)
	}
	if e.registry != nil {
		if err := e.registry.RetireExecutable(ctx, id, actor, "scenario deleted by operator"); err != nil {
			return fmt.Errorf("content registry: retire %s: %w", id, err)
		}
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

func yamlUnmarshal(b []byte, v any) error { return yaml.Unmarshal(b, v) }
