package exercise

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// varPattern matches ${VarName} placeholders anywhere in a string.
var varPattern = regexp.MustCompile(`\$\{([^}]+)\}`)

// Resolver substitutes ${VarName} references in step configs.
// Build one per execution (via NewResolver) and reuse it across all steps.
type Resolver struct {
	values map[string]string
}

// NewResolver builds a resolver from the plan's variable definitions, the
// operator-provided values for this execution, and built-in system variables.
// Secret variables are resolved from the OS environment at construction time.
func NewResolver(defs []VarDef, provided map[string]string, execID, actor string) *Resolver {
	vals := make(map[string]string, len(defs)+8)

	// ── System variables (always available) ──────────────────────────────────
	vals["ExecutionID"] = execID
	vals["Timestamp"] = time.Now().UTC().Format(time.RFC3339)
	vals["CurrentUser"] = actor

	// ── Plan variable defaults ────────────────────────────────────────────────
	for _, d := range defs {
		switch d.Type {
		case VarTypeSecret:
			if d.SecretEnv != "" {
				vals[d.Name] = os.Getenv(d.SecretEnv)
			}
		case VarTypeRuntime:
			// Runtime vars (e.g. TrackingURL) are injected by the relevant step
			// handler; nothing to pre-populate here.
		default:
			if d.Default != "" {
				vals[d.Name] = d.Default
			}
		}
	}

	// ── Operator-provided values win ─────────────────────────────────────────
	for k, v := range provided {
		vals[k] = v
	}

	return &Resolver{values: vals}
}

// Set injects a runtime-generated value (e.g. TrackingURL minted by the SMTP
// injector) so subsequent steps can reference it.
func (r *Resolver) Set(name, value string) { r.values[name] = value }

// Sub replaces all ${VarName} references in s. Unknown names are left as-is.
func (r *Resolver) Sub(s string) string {
	return varPattern.ReplaceAllStringFunc(s, func(match string) string {
		name := match[2 : len(match)-1] // strip ${ and }
		if v, ok := r.values[name]; ok {
			return v
		}
		return match
	})
}

// ResolveStepConfig substitutes all ${VarName} references in every string field
// of a StepConfig. Uses a JSON round-trip so no field enumeration is needed.
// The substitution is JSON-aware: replacement values are escaped so they can't
// break the JSON structure (a value containing a quote is safe).
func (r *Resolver) ResolveStepConfig(cfg StepConfig) (StepConfig, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return cfg, err
	}

	// The raw bytes are a valid JSON object. We need to replace ${VarName}
	// occurrences that appear inside JSON string values (i.e. between quotes).
	// We JSON-encode each replacement value to get a safe escaped string, then
	// strip the outer quotes because we're inserting inside an existing string.
	substituted := varPattern.ReplaceAllStringFunc(string(raw), func(match string) string {
		name := match[2 : len(match)-1]
		v, ok := r.values[name]
		if !ok {
			return match
		}
		// json.Marshal("...") → `"escaped"` — drop the surrounding quotes.
		b, merr := json.Marshal(v)
		if merr != nil || len(b) < 2 {
			return match
		}
		return string(b[1 : len(b)-1])
	})

	var out StepConfig
	if err := json.Unmarshal([]byte(substituted), &out); err != nil {
		return cfg, fmt.Errorf("variable resolution produced invalid JSON: %w", err)
	}
	return out, nil
}

// ValidateVars checks that all required, non-secret, non-runtime variables
// have been supplied (either via provided or via a default in defs).
// Returns nil if all requirements are met.
func ValidateVars(defs []VarDef, provided map[string]string) error {
	var missing []string
	for _, d := range defs {
		if !d.Required {
			continue
		}
		if d.Type == VarTypeSecret || d.Type == VarTypeRuntime {
			continue
		}
		if _, ok := provided[d.Name]; ok {
			continue
		}
		if d.Default != "" {
			continue
		}
		missing = append(missing, d.Name)
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required variables: %s", strings.Join(missing, ", "))
	}
	return nil
}

// ExtractVarRefs returns the unique ${VarName} references in a step's config JSON.
func ExtractVarRefs(ps *PlanStep) []string {
	raw, _ := json.Marshal(ps.Config)
	matches := varPattern.FindAllSubmatch(raw, -1)
	seen := make(map[string]bool)
	var names []string
	for _, m := range matches {
		if len(m) >= 2 {
			name := string(m[1])
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	return names
}
