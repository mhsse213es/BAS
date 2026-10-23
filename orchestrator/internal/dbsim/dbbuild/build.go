// Package dbbuild compiles a signed dbsim scenario into the agent-facing
// steps. It lives apart from internal/dbsim because it imports
// internal/scenario (which other dbsim tests' dependencies already import),
// and internal/dbsim must stay a leaf.
//
// Trust boundaries enforced here:
//   - A step names a target by id only. Host, port, database, TLS mode,
//     expected identity, credential reference, mode and the trust flags come
//     solely from the dbsim.TargetResolver.
//   - RunID and the per-step Marker are generated here, per build, never read
//     from YAML or request input.
//   - The orchestrator-side gate (dbsim.Authorize) runs before any step is
//     emitted; a refusal fails the whole build.
//   - The emitted step has exactly the shape the agent accepts (see
//     agent/exec_dbprobe.go dbprobeStepShapeRefusal and expectedExecClass).
package dbbuild

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/scenario"
)

// MarkerPrefix and RunIDPrefix tag everything this package issues. Both stay
// within the adapters' sanitizer alphabet [A-Za-z0-9._:-].
const (
	MarkerPrefix = "bas-dbsim:"
	RunIDPrefix  = "bas-dbsim-run:"
)

// CredentialRefPrefix is required on every target's credential reference.
const CredentialRefPrefix = "dbcred:"

// DefaultLimits apply when a step requests none.
var DefaultLimits = dbsim.Limits{MaxRows: 100, TimeoutSec: 30, MaxConns: 1}

// Options carries the per-dispatch inputs.
type Options struct {
	Resolver dbsim.TargetResolver
	// ClientEnabled mirrors the Admin setting that permits client-mode runs
	// (default off). It is a server setting, never request input.
	ClientEnabled bool
	// MutationApproved is the scenario record's approval for non-read_only
	// probes. Never request input.
	MutationApproved bool
	// RunExpiry is required; the dbsim gate refuses a run without one.
	RunExpiry time.Time
	// Now is an optional clock (zero means time.Now).
	Now func() time.Time
	// RunID overrides the generated run id (tests). Empty generates one.
	RunID string
}

// ProbeActionKey is the catalog action key issued for a probe class.
func ProbeActionKey(c dbsim.ProbeClass) string { return "dbprobe_" + string(c) }

// ExpectedExecutionClass maps a probe class to the ExecutionClass the agent
// requires on the signed step (spec A6; mirrors agent expectedExecClass).
func ExpectedExecutionClass(c dbsim.ProbeClass) scenario.ExecutionClass {
	switch c {
	case dbsim.ClassReadOnly:
		return scenario.ClassNonDestructive
	case dbsim.ClassBoundedSynthetic:
		return scenario.ClassPotentiallyDestructive
	default:
		return scenario.ClassDestructive
	}
}

func randHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("dbbuild: random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// BuildSteps compiles every step of a dbsim scenario. All steps must be
// dbprobe steps. Nothing is returned on error, so a partially authorised
// scenario is never dispatched.
func BuildSteps(ctx context.Context, sc *scenario.Scenario, opt Options) ([]scenario.ScenarioStep, error) {
	if sc == nil {
		return nil, fmt.Errorf("dbbuild: nil scenario")
	}
	if opt.Resolver == nil {
		return nil, fmt.Errorf("dbbuild: no target resolver")
	}
	if err := sc.ValidateDBProbeSteps(); err != nil {
		return nil, fmt.Errorf("dbbuild: %w", err)
	}
	if len(sc.Steps) == 0 {
		return nil, fmt.Errorf("dbbuild: scenario %q has no steps", sc.ID)
	}
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}
	runID := opt.RunID
	if runID == "" {
		h, err := randHex(8)
		if err != nil {
			return nil, err
		}
		runID = RunIDPrefix + h
	}

	steps := make([]scenario.ScenarioStep, 0, len(sc.Steps))
	classes := make([]dbsim.ProbeClass, 0, len(sc.Steps))
	seenTask := map[string]bool{}
	for i, st := range sc.Steps {
		if !strings.EqualFold(st.Executor, scenario.ExecutorDBProbe) {
			return nil, fmt.Errorf("dbbuild: step %d (%q): a dbsim scenario may contain only dbprobe steps", i+1, st.Name)
		}
		entry, ok := dbsim.LookupProbeEntry(st.DBProbe)
		if !ok {
			return nil, fmt.Errorf("dbbuild: step %d (%q): unknown probe %q", i+1, st.Name, st.DBProbe)
		}
		if err := checkParams(entry, st.DBParams); err != nil {
			return nil, fmt.Errorf("dbbuild: step %d (%q): %w", i+1, st.Name, err)
		}
		if err := checkFixture(entry, st); err != nil {
			return nil, fmt.Errorf("dbbuild: step %d (%q): %w", i+1, st.Name, err)
		}
		target, err := opt.Resolver.Resolve(ctx, st.DBTarget)
		if err != nil {
			return nil, fmt.Errorf("dbbuild: step %d (%q): resolve target %q: %w", i+1, st.Name, st.DBTarget, err)
		}
		if err := dbsim.Authorize(target, entry, dbsim.AuthInput{
			ClientEnabled: opt.ClientEnabled, MutationApproved: opt.MutationApproved,
			RunExpiry: opt.RunExpiry, Now: now(),
		}); err != nil {
			return nil, fmt.Errorf("dbbuild: step %d (%q): %w", i+1, st.Name, err)
		}
		if !strings.HasPrefix(target.CredentialRef, CredentialRefPrefix) || len(target.CredentialRef) == len(CredentialRefPrefix) {
			return nil, fmt.Errorf("dbbuild: step %d (%q): target %q has no %q credential reference", i+1, st.Name, target.ID, CredentialRefPrefix)
		}
		if strings.TrimSpace(target.Host) == "" {
			return nil, fmt.Errorf("dbbuild: step %d (%q): target %q has no host", i+1, st.Name, target.ID)
		}
		limits := DefaultLimits
		if st.DBLimits != nil {
			limits = dbsim.Limits{MaxRows: st.DBLimits.MaxRows, TimeoutSec: st.DBLimits.TimeoutSec, MaxConns: st.DBLimits.MaxConns}
		}
		mh, err := randHex(12)
		if err != nil {
			return nil, err
		}
		spec := dbsim.DBProbeSpec{
			Engine: target.Engine, ProbeID: entry.ID, TargetID: target.ID,
			Host: target.Host, Port: target.Port, Database: target.Database, TLSMode: target.TLSMode,
			ExpectedIdentity: target.ExpectedIdentity, CredentialRef: target.CredentialRef,
			RunID: runID, Marker: MarkerPrefix + mh, FixtureID: st.DBFixture,
			Mode: target.Mode, Limits: limits, Params: copyParams(st.DBParams),
		}
		raw, err := json.Marshal(spec)
		if err != nil {
			return nil, fmt.Errorf("dbbuild: step %d (%q): marshal spec: %w", i+1, st.Name, err)
		}
		taskID := scenario.TaskID(st.TechniqueID, st.Name)
		if seenTask[taskID] {
			return nil, fmt.Errorf("dbbuild: step %d (%q): duplicate technique/name pair", i+1, st.Name)
		}
		seenTask[taskID] = true
		steps = append(steps, scenario.ScenarioStep{
			TaskID: taskID, TechniqueID: st.TechniqueID, Name: st.Name, Framework: "custom",
			Executor:   scenario.ExecutorDBProbe,
			Command:    entry.ID, // non-executable text: exactly the probe id
			TimeoutSec: limits.TimeoutSec + 10,
			ActionKey:  ProbeActionKey(entry.Class),
			DBProbe:    raw,
		})
		classes = append(classes, entry.Class)
	}

	scenario.AttachExecutionClassifications(steps)
	for i := range steps {
		if want := ExpectedExecutionClass(classes[i]); steps[i].ExecutionClass != want {
			return nil, fmt.Errorf("dbbuild: step %q resolved execution class %q, want %q (catalog entry missing for technique %q?)",
				steps[i].Name, steps[i].ExecutionClass, want, steps[i].TechniqueID)
		}
	}
	return steps, nil
}

// fixtureTablePat is a bare fixture table name: it mirrors the agent's fixture
// identifier shape, so a schema-qualified or quoted value can never be a param.
var fixtureTablePat = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// checkFixture enforces the fixture rules of the registry entry: a
// fixture-aware probe needs db_fixture and a bare table name in its fixture
// param (the agent resolves it to the active fixture's schema, spec R-Z); a
// probe that does not read a fixture must not carry one.
func checkFixture(e dbsim.ProbeRegistryEntry, st scenario.Step) error {
	if e.FixtureParam == "" {
		if st.DBFixture != "" {
			return fmt.Errorf("probe %q does not use a fixture; db_fixture must be empty", e.ID)
		}
		return nil
	}
	if st.DBFixture == "" {
		return fmt.Errorf("probe %q reads a seeded fixture and requires db_fixture", e.ID)
	}
	if v := st.DBParams[e.FixtureParam]; !fixtureTablePat.MatchString(v) {
		return fmt.Errorf("param %q must be a bare fixture table name", e.FixtureParam)
	}
	return nil
}

func copyParams(p map[string]string) map[string]string {
	if len(p) == 0 {
		return nil
	}
	out := make(map[string]string, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}

// checkParams enforces the registry's parameter schema: every param declared,
// and values parse as their declared kind.
func checkParams(e dbsim.ProbeRegistryEntry, params map[string]string) error {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		kind, ok := e.ParamSchema[k]
		if !ok {
			return fmt.Errorf("param %q not declared for probe %q", k, e.ID)
		}
		v := params[k]
		switch kind {
		case "int":
			if _, err := strconv.Atoi(v); err != nil {
				return fmt.Errorf("param %q must be an integer", k)
			}
		case "bool":
			if _, err := strconv.ParseBool(v); err != nil {
				return fmt.Errorf("param %q must be a boolean", k)
			}
		case "string":
			if v == "" {
				return fmt.Errorf("param %q must not be empty", k)
			}
		}
	}
	return nil
}
