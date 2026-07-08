package scenario

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/integrity"
)

// Detection profile loading, validation, and resolution.
//
// Profiles live at <scenariosDir>/detection-profiles/*.yaml. Each is signed by
// the build pipeline (build.ps1 signs scenarios/**/*.yaml) and verified here the
// same way builtin scenarios are. A step references profiles by name; resolution
// expands the referenced profiles (recursively applying `extends`) and merges
// the step's inline expectations, keyed by expectation id.

// loadProfiles walks the detection-profiles subdir, verifies signatures, parses,
// validates, and registers each profile. Errors are logged and the offending
// profile is skipped — one bad profile never blocks the rest, and never loads a
// half-valid profile into the map.
func (e *Engine) loadProfiles() {
	e.profiles = make(map[string]*DetectionProfile)
	dir := filepath.Join(e.dir, profilesSubdir)
	if _, err := os.Stat(dir); err != nil {
		return // no profiles directory — feature simply inactive
	}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		// Profiles are builtin vendor content → must be signature-verified.
		if err := integrity.VerifyScenarioFile(path); err != nil {
			log.Printf("[!] TAMPER ALERT: detection profile %s failed signature verification: %v — refusing to load", path, err)
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[!] detection profile: read %s: %v — skipping", path, err)
			return nil
		}
		var p DetectionProfile
		if err := yaml.Unmarshal(b, &p); err != nil {
			log.Printf("[!] detection profile: parse %s: %v — skipping", path, err)
			return nil
		}
		p.Source = "builtin"
		if err := validateProfile(&p); err != nil {
			log.Printf("[!] detection profile %s invalid: %v — skipping", path, err)
			return nil
		}
		if _, dup := e.profiles[p.Profile]; dup {
			log.Printf("[!] detection profile: duplicate name %q in %s — skipping", p.Profile, path)
			return nil
		}
		e.profiles[p.Profile] = &p
		return nil
	})
	// Cross-profile checks that need the full set (inheritance targets + cycles).
	for name, p := range e.profiles {
		if err := checkInheritance(name, p, e.profiles, nil); err != nil {
			log.Printf("[!] detection profile %q: %v — removing from registry", name, err)
			delete(e.profiles, name)
		}
	}
}

// Profiles returns a snapshot map of loaded profiles (name → profile).
func (e *Engine) Profiles() map[string]*DetectionProfile { return e.profiles }

// validateProfile checks a single profile's own fields (structural validation
// that does not need the full profile set). Returns the first problem found.
func validateProfile(p *DetectionProfile) error {
	if strings.TrimSpace(p.Profile) == "" {
		return fmt.Errorf("missing 'profile' name")
	}
	if p.Version < 1 {
		return fmt.Errorf("profile %q has invalid version %d (must be >= 1)", p.Profile, p.Version)
	}
	seen := map[string]bool{}
	for i, exp := range p.Expected {
		if err := validateExpectation(exp); err != nil {
			return fmt.Errorf("expectation %d: %w", i+1, err)
		}
		if seen[exp.ID] {
			return fmt.Errorf("duplicate expectation id %q", exp.ID)
		}
		seen[exp.ID] = true
	}
	return nil
}

// validateExpectation checks one expected detection's required fields and enum
// values. Provider must be registered; verification/confidence must be known.
func validateExpectation(exp ExpectedDetection) error {
	if strings.TrimSpace(exp.ID) == "" {
		return fmt.Errorf("missing 'id'")
	}
	if _, ok := LookupProvider(exp.Provider); !ok {
		return fmt.Errorf("unknown provider %q (register it in the Provider Registry)", exp.Provider)
	}
	switch exp.Confidence {
	case ConfidenceRequired, ConfidenceRecommended, ConfidenceOptional:
	default:
		return fmt.Errorf("id %q: invalid confidence %q (want required|recommended|optional)", exp.ID, exp.Confidence)
	}
	switch exp.Verification {
	case "", VerificationAutomatic, VerificationManual, VerificationAPI:
	default:
		return fmt.Errorf("id %q: invalid verification %q (want automatic|manual|api)", exp.ID, exp.Verification)
	}
	if exp.Type != "" && !validDomain(exp.Type) {
		return fmt.Errorf("id %q: invalid type/domain %q", exp.ID, exp.Type)
	}
	// A required-confidence expectation must carry a finding so the report can
	// emit something concrete on a False Silence gap.
	if exp.Confidence == ConfidenceRequired {
		if strings.TrimSpace(exp.Finding.Title) == "" || strings.TrimSpace(exp.Finding.Severity) == "" {
			return fmt.Errorf("id %q: required expectations must define finding.title and finding.severity", exp.ID)
		}
	}
	return nil
}

func validDomain(d string) bool {
	switch d {
	case DomainEndpoint, DomainIdentity, DomainNetwork, DomainCloud, DomainEmail, DomainDLP, DomainSIEM:
		return true
	}
	return false
}

// checkInheritance verifies every `extends` target exists and there is no cycle.
// `stack` tracks the current resolution path for cycle detection.
func checkInheritance(name string, p *DetectionProfile, all map[string]*DetectionProfile, stack []string) error {
	for _, s := range stack {
		if s == name {
			return fmt.Errorf("circular extends: %s", strings.Join(append(stack, name), " -> "))
		}
	}
	stack = append(stack, name)
	for _, parent := range p.Extends {
		pp, ok := all[parent]
		if !ok {
			return fmt.Errorf("extends unknown profile %q", parent)
		}
		if err := checkInheritance(parent, pp, all, stack); err != nil {
			return err
		}
	}
	return nil
}

// ResolveStepExpectations expands a step's detection profiles (recursively via
// extends) and merges its inline expectations, returning the effective expected
// detections plus the {profile, version} refs used (for the report audit line).
// Merge precedence, lowest → highest: base (extended) profiles, then the
// referenced profile's own expectations, then the step's inline expectations.
// Later declarations override earlier ones with the same id.
func (e *Engine) ResolveStepExpectations(step Step) ([]ExpectedDetection, []ProfileRef) {
	return ResolveExpectations(step.DetectionProfiles, step.ExpectedDetections, e.profiles)
}

// ResolveExpectations is the pure resolution used by ResolveStepExpectations and
// by tests. profileNames are resolved against `profiles`; inline supplements/
// overrides them; result order is stable (sorted by id) for deterministic
// rendering and golden tests.
func ResolveExpectations(profileNames []string, inline []ExpectedDetection, profiles map[string]*DetectionProfile) ([]ExpectedDetection, []ProfileRef) {
	merged := map[string]ExpectedDetection{}
	refs := map[string]int{}

	var apply func(name string, seen map[string]bool)
	apply = func(name string, seen map[string]bool) {
		if seen[name] {
			return // cycle guard (loader already rejects cycles; defensive)
		}
		seen[name] = true
		p, ok := profiles[name]
		if !ok {
			return
		}
		// Parents first so the child overrides inherited ids.
		for _, parent := range p.Extends {
			apply(parent, seen)
		}
		for _, exp := range p.Expected {
			merged[exp.ID] = exp
		}
		refs[p.Profile] = p.Version
	}

	for _, name := range profileNames {
		apply(name, map[string]bool{})
	}
	// Inline expectations win over anything from profiles.
	for _, exp := range inline {
		merged[exp.ID] = exp
	}

	out := make([]ExpectedDetection, 0, len(merged))
	for _, exp := range merged {
		out = append(out, exp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })

	profileRefs := make([]ProfileRef, 0, len(refs))
	for name, ver := range refs {
		profileRefs = append(profileRefs, ProfileRef{Profile: name, Version: ver})
	}
	sort.Slice(profileRefs, func(i, j int) bool { return profileRefs[i].Profile < profileRefs[j].Profile })

	return out, profileRefs
}
