// Package avscenario connects internal/avcatalog vectors to the existing
// agent-dispatch and execution path (internal/scenario) -- av.txt §5's
// "Scenario adapters" row. It builds no new dispatch mechanism: the
// scenario.Scenario/Step values it produces are the exact same shape every
// scenarios/endpoint-mastery/em-*.yaml scenario already uses, so a scenario
// built here flows through the existing agent dispatch, RBAC/authorization,
// timeout, and run-reporting path unchanged. It depends on avcatalog and
// internal/scenario; neither depends on it.
//
// Not every vector in the catalog is concretely dispatchable today: a
// vector whose ExecutionTemplate.Executor is not one of the agent's real
// supported executors (powershell, cmd, wmi, mshta, rundll32, cscript,
// wscript, regsvr32, schtasks) needs a dedicated test harness that does not
// exist yet. Every current real seed vector now ships a real harness this
// way, including AV-BEHAV-001's process-injection simulator (an in-memory
// Add-Type P/Invoke probe, not a separate binary artifact -- see
// catalog_behavioral.go's harness-contract doc comment); this mechanism
// stays in place for any future vector that genuinely needs a capability
// no standard executor provides. BuildStep rejects those explicitly with
// ErrHarnessRequired rather than silently producing an undispatchable step
// -- this package never fabricates a command the catalog didn't declare.
package avscenario

import (
	"errors"
	"fmt"

	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/scenario"
)

// ErrHarnessRequired is returned by BuildStep/BuildCounterpartStep when a
// vector's ExecutionTemplate names an executor the agent does not support
// directly -- the vector needs a dedicated test harness binary that has not
// been built yet.
var ErrHarnessRequired = errors.New("vector requires a dedicated test harness not yet built; not dispatchable through a standard executor")

// agentExecutors is the real, current set of executors the agent supports,
// per scenario.ScenarioStep.Executor's own documented vocabulary.
var agentExecutors = map[string]bool{
	"powershell": true, "cmd": true, "wmi": true, "mshta": true,
	"rundll32": true, "cscript": true, "wscript": true,
	"regsvr32": true, "schtasks": true,
}

// defaultTimeoutSec is applied to every adapted step. avcatalog vectors do
// not declare a per-vector timeout -- a single conservative default reuses
// the existing timeout mechanism uniformly rather than requiring new
// catalog authoring.
const defaultTimeoutSec = 30

// PlatformToOS maps an avcatalog.Platform to the scenario.Scenario.SupportedOS
// vocabulary ("windows"/"linux"/"darwin").
func PlatformToOS(p avcatalog.Platform) (string, error) {
	switch p {
	case avcatalog.PlatformWindowsWorkstation, avcatalog.PlatformWindowsServer:
		return "windows", nil
	case avcatalog.PlatformLinuxServer:
		return "linux", nil
	case avcatalog.PlatformMacOS:
		return "darwin", nil
	default:
		return "", fmt.Errorf("platform %q has no known scenario.SupportedOS mapping", p)
	}
}

// SupportedOS computes the deduplicated scenario.Scenario.SupportedOS list
// for vector's declared platforms, in declaration order.
func SupportedOS(vector avcatalog.Vector) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, p := range vector.Platforms {
		osName, err := PlatformToOS(p)
		if err != nil {
			return nil, fmt.Errorf("vector %q: %w", vector.ID, err)
		}
		if !seen[osName] {
			seen[osName] = true
			out = append(out, osName)
		}
	}
	return out, nil
}

// buildStepFromExecution builds one agent-dispatchable Step from an
// ExecutionTemplate, carrying the vector's ATT&CK technique and provenance
// through to the step's existing reporting fields. It returns
// ErrHarnessRequired, wrapped with the offending executor, when exec's
// Executor is not one the agent supports directly.
func buildStepFromExecution(vector avcatalog.Vector, legLabel string, exec avcatalog.ExecutionTemplate) (scenario.Step, error) {
	if !agentExecutors[exec.Executor] {
		return scenario.Step{}, fmt.Errorf("vector %q %s leg: executor %q: %w", vector.ID, legLabel, exec.Executor, ErrHarnessRequired)
	}
	technique := ""
	if len(vector.Standards.ATTACKTechniques) > 0 {
		technique = vector.Standards.ATTACKTechniques[0]
	}
	step := scenario.Step{
		Name:        fmt.Sprintf("%s: %s (%s)", vector.ID, vector.Name, legLabel),
		TechniqueID: technique,
		Framework:   "custom",
		Executor:    exec.Executor,
		Command:     exec.Command,
		TimeoutSec:  defaultTimeoutSec,
		Cleanup:     exec.CleanupCommand,
		// Every avcatalog vector is authored as a harmless, disposable,
		// purpose-built simulation (av.txt §2's own repeated framing), never
		// a real attack payload -- so it is always telemetry-safe and
		// production-safe, reversible by its own cleanup requirement. This
		// is a documented authoring convention, not a property avcatalog's
		// own validation currently enforces.
		Fidelity:       "",
		ProductionSafe: true,
		Reversible:     true,
		BlastRadius:    exec.Description,
	}
	if vector.Provenance != "" {
		step.ThreatIntelSources = []scenario.ThreatIntelSource{{Reference: vector.Provenance}}
	}
	return step, nil
}

// BuildPrimaryStep builds the dispatchable Step for vector's primary
// execution leg.
func BuildPrimaryStep(vector avcatalog.Vector) (scenario.Step, error) {
	return buildStepFromExecution(vector, string(avcatalog.LegPrimary), vector.Primary)
}

// BuildCounterpartStep builds the dispatchable Step for vector's
// counterpart leg. ok is false when vector has no counterpart at all (never
// an error in that case -- a missing counterpart is a valid catalog state).
func BuildCounterpartStep(vector avcatalog.Vector) (step scenario.Step, ok bool, err error) {
	if vector.Counterpart == nil {
		return scenario.Step{}, false, nil
	}
	step, err = buildStepFromExecution(vector, string(avcatalog.LegCounterpart), *vector.Counterpart)
	if err != nil {
		return scenario.Step{}, false, err
	}
	return step, true, nil
}

// BuildScenario bundles vectors' primary (and, when present, counterpart)
// steps into one real, dispatchable scenario.Scenario -- the SAME shape
// scenarios/endpoint-mastery/em-*.yaml already uses, so it flows through
// the existing agent-dispatch, authorization, and run-reporting path
// unchanged. id must satisfy scenario.Scenario's own id pattern (lowercase
// letters/digits/hyphens) -- it is the adapted scenario's OWN identifier,
// never a catalog vector ID (which is uppercase and would be rejected).
// The built scenario is validated via the real scenario.Scenario.Validate()
// before being returned, never a reimplementation of its checks.
func BuildScenario(id, name, description string, vectors []avcatalog.Vector) (scenario.Scenario, error) {
	if len(vectors) == 0 {
		return scenario.Scenario{}, fmt.Errorf("at least one vector is required")
	}
	var steps []scenario.Step
	osSeen := map[string]bool{}
	var supportedOS []string
	for _, v := range vectors {
		primary, err := BuildPrimaryStep(v)
		if err != nil {
			return scenario.Scenario{}, err
		}
		steps = append(steps, primary)

		if counterpart, ok, err := BuildCounterpartStep(v); err != nil {
			return scenario.Scenario{}, err
		} else if ok {
			steps = append(steps, counterpart)
		}

		vectorOS, err := SupportedOS(v)
		if err != nil {
			return scenario.Scenario{}, err
		}
		for _, osName := range vectorOS {
			if !osSeen[osName] {
				osSeen[osName] = true
				supportedOS = append(supportedOS, osName)
			}
		}
	}

	s := scenario.Scenario{
		ID: id, Name: name, Description: description,
		Steps: steps, Executable: true, SupportedOS: supportedOS,
	}
	if err := s.Validate(); err != nil {
		return scenario.Scenario{}, fmt.Errorf("built scenario failed validation: %w", err)
	}
	return s, nil
}
