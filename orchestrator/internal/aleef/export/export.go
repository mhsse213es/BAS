// Package export turns a verified ALEEF finding into a regression and checks
// later builds against it.
//
// A Regression is the Aleef-native executable form: a Bundle (JSON, no
// timestamps, deterministic) holding the test and both controls under
// ALEEF-REG-NNNN ids. The Bundle can always be replayed through package exec,
// which applies the property's own oracle. A catalogue scenario (YAML) is
// produced only when the runner's own grade is authoritative for the oracle
// (OracleRunnerGrade with both runner signals valid); for every other oracle
// the runner grade alone would mis-grade the scenario, so no YAML is emitted
// and the note says so.
//
// Check replays a bundle against a build and says whether the flaw is gone.
// It never marks anything verified and never writes to the store: the caller
// decides whether to reopen or close the finding.
//
// The package is on the generator side: it must not import the benchmark
// bank, its sealed data or the bench harness.
package export

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/aleef/exec"
	"github.com/audspect/bas/internal/aleef/generate"
	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/property"
	"github.com/audspect/bas/internal/aleef/store"
	"github.com/audspect/bas/internal/aleef/verify"
	"github.com/audspect/bas/internal/apibas/runner"
)

// BundleVersion is the only bundle format version this package reads.
const BundleVersion = 1

// Bundle is the Aleef-native executable regression.
type Bundle struct {
	Version      int           `json:"version"`
	RegressionID string        `json:"regression_id"`
	FindingID    string        `json:"finding_id"`
	EvidenceHash string        `json:"evidence_hash"`
	Property     string        `json:"property"`
	Test         generate.Test `json:"test"`
}

// Regression is the export of one verified finding.
type Regression struct {
	Bundle     Bundle
	BundleJSON []byte
	// ScenarioYAML is a catalogue scenario, or nil when the runner's grade
	// alone would mis-grade this oracle (see YAMLNote).
	ScenarioYAML []byte
	YAMLNote     string
}

var regIDPattern = regexp.MustCompile(`^ALEEF-REG-\d{4}$`)

// ToRegression exports a verified finding. It refuses anything that is not
// verified with evidence, whose test does not match, or that has no controls.
// seq is the registry serial (1..9999). The input test is not modified.
func ToRegression(f store.Finding, t generate.Test, seq int) (Regression, error) {
	switch {
	case f.State != store.StateVerified:
		return Regression{}, fmt.Errorf("export: finding %s is %q: only verified findings are exported", f.ID, f.State)
	case f.EvidenceHash == "":
		return Regression{}, fmt.Errorf("export: finding %s has no evidence hash", f.ID)
	case f.TestID != t.ID:
		return Regression{}, fmt.Errorf("export: finding %s is for test %s, not %s", f.ID, f.TestID, t.ID)
	case f.Property != "" && f.Property != t.Property:
		return Regression{}, fmt.Errorf("export: finding %s is for property %s, not %s", f.ID, f.Property, t.Property)
	case t.ControlsBlocked || t.OwnerControl == nil || t.NegativeControl == nil:
		return Regression{}, fmt.Errorf("export: test %s has no controls", t.ID)
	case seq < 1 || seq > 9999:
		return Regression{}, fmt.Errorf("export: serial %d outside 1..9999", seq)
	}
	regID := fmt.Sprintf("ALEEF-REG-%04d", seq)

	rt, err := deepCopy(t)
	if err != nil {
		return Regression{}, err
	}
	rt.ID, rt.Scenario.ID, rt.Scenario.Category = regID, regID, "ALEEF"
	rt.Covered = false
	rt.OwnerControl.ID, rt.OwnerControl.Scenario.ID = regID+"-OC", regID+"-OC"
	rt.NegativeControl.ID, rt.NegativeControl.Scenario.ID = regID+"-NC", regID+"-NC"
	// The controls live on the Test; the template's copies would only duplicate them.
	rt.Template.OwnerControl, rt.Template.NegativeControl = nil, nil

	b := Bundle{Version: BundleVersion, RegressionID: regID, FindingID: f.ID, EvidenceHash: f.EvidenceHash, Property: t.Property, Test: rt}
	if err := validateBundle(b); err != nil {
		return Regression{}, err
	}
	raw, err := MarshalBundle(b)
	if err != nil {
		return Regression{}, err
	}
	reg := Regression{Bundle: b, BundleJSON: raw}

	if rt.Template.Oracle == property.OracleRunnerGrade && rt.Template.RunnerLeakValid && rt.Template.RunnerStateValid {
		y, err := scenarioYAML(b)
		if err != nil {
			return Regression{}, err
		}
		reg.ScenarioYAML = y
	} else {
		reg.YAMLNote = fmt.Sprintf("no catalogue scenario: the %q oracle of %s is not decided by the runner grade alone "+
			"(runner leak valid=%t, runner state valid=%t), which would mis-grade it; replay the bundle through exec instead",
			rt.Template.Oracle, t.Property, rt.Template.RunnerLeakValid, rt.Template.RunnerStateValid)
	}
	return reg, nil
}

func deepCopy(t generate.Test) (generate.Test, error) {
	raw, err := json.Marshal(t)
	if err != nil {
		return generate.Test{}, fmt.Errorf("export: copy test: %w", err)
	}
	var out generate.Test
	if err := json.Unmarshal(raw, &out); err != nil {
		return generate.Test{}, fmt.Errorf("export: copy test: %w", err)
	}
	return out, nil
}

func scenarioYAML(b Bundle) ([]byte, error) {
	s := b.Test.Scenario
	s.NegativeTests = []string{"The fixed build must PASS this scenario: " + s.ExpectedControl}
	s.IndustryMapping, s.RegulatoryMapping = []string{}, []string{}
	if s.SideEffectClass == "STATE_CHANGE_SANDBOX" && len(s.Cleanup) == 0 {
		s.Cleanup = []string{"reset"}
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("export: scenario %s: %w", s.ID, err)
	}
	body, err := yaml.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("export: encode scenario %s: %w", s.ID, err)
	}
	head := fmt.Sprintf("# ALEEF regression %s\n# finding: %s\n# evidence: %s\n", b.RegressionID, b.FindingID, b.EvidenceHash)
	return append([]byte(head), body...), nil
}

// MarshalBundle encodes b deterministically (fixed field order, sorted map
// keys, no timestamps).
func MarshalBundle(b Bundle) ([]byte, error) {
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("export: encode bundle: %w", err)
	}
	return append(raw, '\n'), nil
}

// UnmarshalBundle decodes and validates a bundle: the version, every embedded
// scenario against the contract, and the presence of both controls.
func UnmarshalBundle(data []byte) (Bundle, error) {
	var b Bundle
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return Bundle{}, fmt.Errorf("export: decode bundle: %w", err)
	}
	if err := validateBundle(b); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

func validateBundle(b Bundle) error {
	if b.Version != BundleVersion {
		return fmt.Errorf("export: bundle version %d is not supported (want %d)", b.Version, BundleVersion)
	}
	if !regIDPattern.MatchString(b.RegressionID) {
		return fmt.Errorf("export: regression id %q is malformed", b.RegressionID)
	}
	if b.FindingID == "" || b.EvidenceHash == "" {
		return errors.New("export: bundle lacks a finding id or evidence hash")
	}
	t := b.Test
	if t.ID != b.RegressionID || t.Scenario.ID != b.RegressionID {
		return fmt.Errorf("export: bundle test ids do not match %s", b.RegressionID)
	}
	if t.ControlsBlocked || t.OwnerControl == nil || t.NegativeControl == nil {
		return fmt.Errorf("export: bundle %s has no controls", b.RegressionID)
	}
	for _, c := range []struct {
		t    generate.Test
		want string
	}{{t, b.RegressionID}, {*t.OwnerControl, b.RegressionID + "-OC"}, {*t.NegativeControl, b.RegressionID + "-NC"}} {
		if c.t.ID != c.want || c.t.Scenario.ID != c.want {
			return fmt.Errorf("export: bundle test id %q, want %q", c.t.ID, c.want)
		}
		if err := c.t.Scenario.Validate(); err != nil {
			return fmt.Errorf("export: bundle %s: %w", c.want, err)
		}
	}
	return nil
}

// Outcome is the result of replaying a regression.
type Outcome string

const (
	// FixedConfirmed: the test no longer finds the flaw and the owner control
	// proves the environment sound.
	FixedConfirmed Outcome = "fixed_confirmed"
	// StillVulnerable: the test still finds the flaw.
	StillVulnerable Outcome = "still_vulnerable"
	// Inconclusive: nothing can be concluded (environment, control, cleanup
	// or execution problem).
	Inconclusive Outcome = "inconclusive"
)

// Check replays the regression. The test runs on one fresh environment; only
// when it finds nothing does the owner control run, on a second fresh
// environment, to prove that a No means the flaw is gone and not that the
// environment is broken. Every environment is cleaned up and a cleanup failure
// makes the outcome Inconclusive. Check never writes to the store.
func Check(ctx context.Context, env verify.Env, b Bundle) (Outcome, error) {
	if err := validateBundle(b); err != nil {
		return Inconclusive, err
	}
	res, err := runFresh(ctx, env, b.Test, "test")
	if err != nil {
		return Inconclusive, err
	}
	switch res.Verdict.Finding {
	case exec.FindingYes:
		return StillVulnerable, nil
	case exec.FindingNo:
	default:
		return Inconclusive, nil
	}
	oc := *b.Test.OwnerControl
	cres, err := runFresh(ctx, env, oc, "owner control")
	if err != nil {
		return Inconclusive, err
	}
	if cres.Verdict.Finding != exec.FindingNo || !property.GradedSuccess(finalResponses(oc, cres)) {
		return Inconclusive, nil
	}
	return FixedConfirmed, nil
}

// runFresh runs one test on its own fresh environment and cleans it up. Any
// problem is returned as an error without tokens or response bodies.
func runFresh(ctx context.Context, env verify.Env, t generate.Test, what string) (exec.Result, error) {
	if err := ctx.Err(); err != nil {
		return exec.Result{}, fmt.Errorf("export: %s not run: %w", what, err)
	}
	ex, cleanup, err := env.Fresh(ctx)
	if err != nil || ex == nil {
		if cleanup != nil {
			_, _ = doCleanup(ctx, cleanup)
		}
		if err == nil {
			err = errors.New("no executor")
		}
		return exec.Result{}, fmt.Errorf("export: fresh environment for %s unavailable: %w", what, err)
	}
	res, rerr := ex.Run(ctx, t)
	orphans, cerr := doCleanup(ctx, cleanup)
	orphans = mergeOrphans(orphans, ex.Orphans())
	if cerr != nil || len(orphans) > 0 || errors.Is(rerr, exec.ErrCleanupFailed) || res.Report.Outcome.Reason == runner.ReasonCleanupFailed {
		if cerr == nil {
			cerr = exec.ErrCleanupFailed
		}
		return exec.Result{}, fmt.Errorf("export: cleanup after %s failed (%d orphan(s)): %w", what, len(orphans), cerr)
	}
	if rerr != nil {
		if ctx.Err() != nil {
			return exec.Result{}, fmt.Errorf("export: %s interrupted: %w", what, ctx.Err())
		}
		return exec.Result{}, fmt.Errorf("export: %s could not be executed", what)
	}
	if ctx.Err() != nil {
		return exec.Result{}, fmt.Errorf("export: %s interrupted: %w", what, ctx.Err())
	}
	return res, nil
}

func doCleanup(ctx context.Context, c func(context.Context) ([]model.CreatedObject, error)) ([]model.CreatedObject, error) {
	if c == nil {
		return nil, nil
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	defer cancel()
	return c(cctx)
}

func mergeOrphans(a, b []model.CreatedObject) []model.CreatedObject {
	out := append([]model.CreatedObject(nil), a...)
	for _, o := range b {
		dup := false
		for _, e := range out {
			if e.ID == o.ID && e.Operation == o.Operation {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, o)
		}
	}
	return out
}

// finalResponses are the responses to the control's last step, after the
// baseline exchange.
func finalResponses(c generate.Test, res exec.Result) []property.Response {
	if len(c.Scenario.Steps) == 0 || len(res.Report.Exchanges) < 2 {
		return nil
	}
	last := c.Scenario.Steps[len(c.Scenario.Steps)-1].ID
	var rs []property.Response
	for _, e := range res.Report.Exchanges[1:] {
		if e.StepID == last {
			rs = append(rs, property.Response{Status: e.Status, Body: []byte(e.Body)})
		}
	}
	return rs
}
