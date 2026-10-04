package exercise

import (
	"fmt"
	"strings"
	"time"
)

// ValidationErrors is a list of human-readable validation errors.
// An empty slice means the plan is valid.
type ValidationErrors []string

func (ve ValidationErrors) Error() string {
	return strings.Join(ve, "; ")
}

// ValidatePlan is the "compiler" for exercise plans.
// It returns all errors so the caller can surface the full picture at once
// rather than fixing one error per round-trip.
func ValidatePlan(p *Plan) ValidationErrors {
	var errs ValidationErrors

	// ── Duplicate / missing IDs ───────────────────────────────────────────────
	ids := make(map[string]bool, len(p.Steps))
	for _, s := range p.Steps {
		if s.ID == "" {
			errs = append(errs, "step is missing an id")
			continue
		}
		if ids[s.ID] {
			errs = append(errs, fmt.Sprintf("duplicate step id %q", s.ID))
		}
		ids[s.ID] = true
	}
	if len(errs) > 0 {
		// Can't do graph analysis with broken IDs — return early.
		return errs
	}

	// ── depends_on references ─────────────────────────────────────────────────
	for _, s := range p.Steps {
		for _, dep := range s.DependsOn {
			if !ids[dep] {
				errs = append(errs, fmt.Sprintf("step %q depends_on unknown step %q", s.ID, dep))
			}
		}
	}

	// ── Cycle detection (DFS colour marking) ─────────────────────────────────
	// Build adjacency: step → its dependencies (reverse of execution direction).
	adj := make(map[string][]string, len(p.Steps))
	for _, s := range p.Steps {
		adj[s.ID] = s.DependsOn
	}
	const (
		white = 0 // unvisited
		gray  = 1 // in current DFS path
		black = 2 // fully explored
	)
	colour := make(map[string]int, len(p.Steps))
	var path []string
	var dfs func(id string) bool
	dfs = func(id string) bool {
		if colour[id] == black {
			return false
		}
		if colour[id] == gray {
			return true // back edge → cycle
		}
		colour[id] = gray
		path = append(path, id)
		for _, dep := range adj[id] {
			if dfs(dep) {
				return true
			}
		}
		path = path[:len(path)-1]
		colour[id] = black
		return false
	}
	for _, s := range p.Steps {
		path = nil
		if dfs(s.ID) {
			errs = append(errs, fmt.Sprintf("circular dependency involving step %q", s.ID))
			break // report one cycle; fixing it may resolve others
		}
	}

	// ── Unreachable nodes ─────────────────────────────────────────────────────
	// A node is reachable if it is a root (no depends_on) OR every node it
	// depends on is itself reachable.  Compute with simple topological order.
	reachable := make(map[string]bool, len(p.Steps))
	changed := true
	for changed {
		changed = false
		for _, s := range p.Steps {
			if reachable[s.ID] {
				continue
			}
			if len(s.DependsOn) == 0 {
				reachable[s.ID] = true
				changed = true
				continue
			}
			allReachable := true
			for _, dep := range s.DependsOn {
				if !reachable[dep] {
					allReachable = false
					break
				}
			}
			if allReachable {
				reachable[s.ID] = true
				changed = true
			}
		}
	}
	for _, s := range p.Steps {
		if !reachable[s.ID] {
			errs = append(errs, fmt.Sprintf("unreachable step %q (check for cycles in its dependency chain)", s.ID))
		}
	}

	// ── Condition expressions ─────────────────────────────────────────────────
	for _, s := range p.Steps {
		if err := validateCondition(s.Condition, ids); err != nil {
			errs = append(errs, fmt.Sprintf("step %q invalid condition: %v", s.ID, err))
		}
	}

	// ── Timeout / duration values ─────────────────────────────────────────────
	for _, s := range p.Steps {
		if s.TimeoutSecs < 0 {
			errs = append(errs, fmt.Sprintf("step %q has negative timeout_secs", s.ID))
		}
		dur := s.Config.WaitDuration
		if dur != "" && !strings.HasPrefix(dur, "${") {
			if _, err := time.ParseDuration(dur); err != nil {
				errs = append(errs, fmt.Sprintf("step %q invalid wait_duration %q: %v", s.ID, dur, err))
			}
		}
	}

	// ── Variable references ───────────────────────────────────────────────────
	// Only checked when the plan declares variables — plans without a variable
	// section may still use ${...} references (they'll resolve to empty at runtime).
	if len(p.Variables) > 0 {
		declared := make(map[string]bool, len(p.Variables)+4)
		for _, v := range p.Variables {
			declared[v.Name] = true
		}
		// System variables always available.
		for _, sys := range []string{"ExecutionID", "Timestamp", "CurrentUser"} {
			declared[sys] = true
		}
		for _, s := range p.Steps {
			for _, ref := range ExtractVarRefs(&s) {
				if !declared[ref] {
					errs = append(errs, fmt.Sprintf("step %q references undeclared variable ${%s}", s.ID, ref))
				}
			}
		}
		// Warn about duplicate variable names.
		varNames := make(map[string]bool)
		for _, v := range p.Variables {
			if varNames[v.Name] {
				errs = append(errs, fmt.Sprintf("duplicate variable name %q", v.Name))
			}
			varNames[v.Name] = true
		}
	}

	return errs
}

// validateCondition checks that a condition expression is syntactically valid
// and only references step IDs that exist in the plan.
func validateCondition(cond string, ids map[string]bool) error {
	cond = strings.TrimSpace(cond)
	if cond == "" || cond == "always" || cond == "true" || cond == "false" || cond == "never" {
		return nil
	}
	// Accepted predicates.
	validPredicates := map[string]bool{
		"clicked": true, "not_clicked": true,
		"reported": true,
		"timeout":  true, "no_timeout": true,
		"succeeded": true, "failed": true,
	}
	parts := strings.SplitN(cond, ":", 3)
	if len(parts) != 3 || parts[0] != "step" {
		return fmt.Errorf("unknown condition format %q (expected \"step:<id>:<predicate>\" or \"always\")", cond)
	}
	stepID, predicate := parts[1], parts[2]
	if stepID == "" {
		return fmt.Errorf("empty step id in condition")
	}
	if !ids[stepID] {
		return fmt.Errorf("references unknown step %q", stepID)
	}
	if !validPredicates[predicate] {
		return fmt.Errorf("unknown predicate %q (valid: %s)", predicate,
			strings.Join(keys(validPredicates), ", "))
	}
	return nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
