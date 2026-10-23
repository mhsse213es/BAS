// Package campaign wires the Aleef components into one runnable discovery
// campaign: import the application model, validate the engagement, build a
// guarded HTTP path, generate tests, and verify every test on fresh
// environments, recording as it goes. The API and the benchmark harness both
// call Run; this package never calls them.
//
//	OpenAPI -> model.Import -> operator classes
//	        -> safety.NewGuard (engagement, scope, budget, breaker)   [refusal: no request sent]
//	        -> generation fixture (BuildFixture via guarded Doer) -> generate.Generate -> cleanup
//	        -> Recorder.CreateRun
//	        -> for each test, in generated order:
//	             stop? (cancel / breaker / kill switch / budget) -> remaining tests "not executed"
//	             Recorder.SaveTest(test, owner control, negative control)
//	             verify.Verify(test)  -- fresh fixture + executor + cleanup per round
//	        -> final sweep: retry every cleanup that did not succeed -> Orphans
//
// Safety: every request is sent through the one Guard. The campaign never
// builds an HTTP client without its transport (the setup client is wrapped
// with Guard.WrapDoer, the executor's client is wrapped by exec.New). Tokens
// are resolved only inside model.BuildFixture and the runner; they never enter
// the Report, an error or a log. The Report holds ids, states, reasons and
// hashes only: no request or response bodies, no raw exchanges.
//
// Tests are generated against one generation fixture but verified on fresh
// fixtures whose server-assigned ids differ; see alias.go for how the two are
// reconciled.
//
// The package is on the executing side: it must not import the benchmark bank,
// its sealed data or the bench harness.
package campaign

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/audspect/bas/internal/aleef/export"
	"github.com/audspect/bas/internal/aleef/generate"
	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/property"
	"github.com/audspect/bas/internal/aleef/safety"
	"github.com/audspect/bas/internal/aleef/store"
	"github.com/audspect/bas/internal/aleef/verify"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/targetscope"
)

// StateNotExecuted is the outcome of a test the campaign never started.
const StateNotExecuted = "not_executed"

// Recorder is the persistence a campaign needs; *store.Store satisfies it.
type Recorder interface {
	verify.Recorder
	SaveTest(ctx context.Context, runID string, t generate.Test) error
	CreateRun(ctx context.Context, engagementID string) (string, error)
	// GetFinding, NextRegressionSeq and SaveRegression persist the regression
	// of every verified finding (see saveRegression).
	GetFinding(ctx context.Context, id string) (store.Finding, error)
	NextRegressionSeq(ctx context.Context) (int, error)
	SaveRegression(ctx context.Context, findingID, regressionID string, bundleJSON, scenarioYAML []byte, yamlNote string) error
	// ListVerifiedWithoutRegression finds verified findings a crash left
	// without a regression (runID "" = all runs); Run demotes them first.
	ListVerifiedWithoutRegression(ctx context.Context, runID string) ([]store.Finding, error)
}

// Options tune generation and verification.
type Options struct {
	Seed          int64
	MaxTests      int
	Variations    []string
	Reproductions int
	// Catalogue is the optional novelty catalogue; nil loads the embedded one.
	Catalogue []contract.Scenario
}

// Config is everything a campaign needs.
type Config struct {
	OpenAPI    []byte
	BaseURL    string
	Engagement safety.Engagement
	Scope      *targetscope.TargetScopeImport
	Accounts   []model.Account
	Setup      []model.SetupOp
	// Classes maps an operation id to its operator-assigned class. An
	// operation without an entry stays unknown and is never executed.
	Classes map[string]model.OpClass
	// Roles ranks the account roles, lowest first (ReservedRoles uses the
	// ranking). Empty derives the roles from Accounts in order of appearance.
	Roles []string

	// Operator declarations for the flow properties.
	Workflow      *property.Workflow
	ReservedRoles map[string]string
	Limits        map[string]int

	Secrets  model.SecretResolver
	Recorder Recorder
	Options  Options
	// HTTP optionally supplies the base Transport and Timeout. Its Transport
	// is wrapped by the guard; redirects are never followed.
	HTTP *http.Client
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
}

// Coverage describes the imported model.
type Coverage struct {
	Operations   int
	Runnable     int // classified read, setup_safe or reversible
	Unclassified int // class unknown: never executed
	ByClass      map[string]int
}

// OpCoverage is the exact coverage of one operation.
type OpCoverage struct {
	Class       string
	Generated   int // tests targeting the operation
	Executed    int
	NotExecuted int
	Findings    int // tests that reproduced at least once (candidate or beyond)
	Verified    int
	// Skipped is the reason the generator produced nothing for the operation
	// ("class unknown", ...), empty otherwise.
	Skipped string
}

// TestOutcome is one test's result. It carries no bodies and no tokens.
type TestOutcome struct {
	TestID    string
	Property  string
	Operation string
	State     string // clean, candidate, verified, rejected, unconfirmed, not_executed
	Reason    string
	// EvidenceHash is empty for anything not verified, including a finding
	// demoted because its regression could not be saved; the stored finding
	// row keeps the hash it was verified with.
	EvidenceHash  string
	Reproductions int
	Executed      bool
	// OwnerControl and NegativeControl are the verifier's recorded control
	// results: true only when that control ran and passed in every round.
	OwnerControl, NegativeControl bool
	// RegressionID is the saved regression of a verified finding.
	RegressionID string
}

// FindingSummary is one finding (a test that reproduced at least once).
type FindingSummary struct {
	FindingID    string // empty when the recorder cannot list findings
	TestID       string
	Property     string
	Operation    string
	State        string
	Reason       string
	EvidenceHash string
	// RegressionID is the id of the regression saved for a verified finding.
	RegressionID string
	// OwnerControl and NegativeControl: see TestOutcome.
	OwnerControl, NegativeControl bool
}

// Report is the campaign result. It never contains tokens, request or response
// bodies or raw exchanges.
type Report struct {
	RunID     string
	Model     Coverage
	Generated generate.Report
	// Total is the number of tests generated; Total == Executed + NotExecuted.
	Total, Executed, NotExecuted int
	// RepairedUnregressed counts verified findings from earlier campaigns that
	// had no regression (the process died between verification and saving it)
	// and were demoted to unconfirmed before this campaign started.
	RepairedUnregressed int
	// RegressionFailed counts findings demoted from verified to unconfirmed
	// because their regression could not be saved.
	RegressionFailed                                                       int
	Clean, ReachedCandidate, Verified, Rejected, Unconfirmed, Inconclusive int
	PerOperation                                                           map[string]OpCoverage
	NotModelled                                                            []string
	Orphans                                                                []model.CreatedObject
	// Halted is the reason the campaign stopped early, and "cleanup failed"
	// when any object could not be compensated.
	Halted   string
	Findings []FindingSummary
	Tests    []TestOutcome
	// Requests and CleanupRequests are the guard's counters.
	Requests, CleanupRequests int
}

var tagSafe = regexp.MustCompile(`[^a-z0-9]+`)

func runTag(e safety.Engagement, seed int64) string {
	id := strings.Trim(tagSafe.ReplaceAllString(strings.ToLower(e.ID), "-"), "-")
	if len(id) > 24 {
		id = id[:24]
	}
	return fmt.Sprintf("%s-%d", id, seed)
}

func validClass(c model.OpClass) bool {
	switch c {
	case model.ClassUnknown, model.ClassRead, model.ClassSetupSafe, model.ClassReversible, model.ClassMoney, model.ClassNotifying:
		return true
	}
	return false
}

// prepare imports the model and applies the operator's classes.
func prepare(cfg Config) (model.Model, error) {
	m, err := model.Import(cfg.OpenAPI)
	if err != nil {
		return m, err
	}
	have := map[string]bool{}
	for i := range m.Operations {
		have[m.Operations[i].ID] = true
		c, ok := cfg.Classes[m.Operations[i].ID]
		if !ok {
			m.Operations[i].Class = model.ClassUnknown
			continue
		}
		if !validClass(c) {
			return m, fmt.Errorf("campaign: operation %q has an invalid class %q", m.Operations[i].ID, c)
		}
		m.Operations[i].Class = c
	}
	var stray []string
	for id := range cfg.Classes {
		if !have[id] {
			stray = append(stray, id)
		}
	}
	if len(stray) > 0 {
		sort.Strings(stray)
		return m, fmt.Errorf("campaign: classes name operations that are not in the model: %s", strings.Join(stray, ", "))
	}
	m.Roles = cfg.Roles
	if len(m.Roles) == 0 {
		seen := map[string]bool{}
		for _, a := range cfg.Accounts {
			if a.Role != "" && !seen[a.Role] {
				seen[a.Role] = true
				m.Roles = append(m.Roles, a.Role)
			}
		}
	}
	return m, nil
}

func coverage(m model.Model) Coverage {
	c := Coverage{Operations: len(m.Operations), ByClass: map[string]int{}}
	for _, op := range m.Operations {
		cl := string(op.Class)
		if cl == "" {
			cl = string(model.ClassUnknown)
		}
		c.ByClass[cl]++
		switch op.Class {
		case model.ClassRead, model.ClassSetupSafe, model.ClassReversible:
			c.Runnable++
		default:
			c.Unclassified++
		}
	}
	return c
}

// Run executes a campaign. It returns an error before any request is sent when
// the configuration or engagement is refused. After that it always cleans up
// everything it created, even when it stops early; a stop is reported in
// Report.Halted, not as an error. Objects that could not be compensated are
// listed in Report.Orphans (the error stays nil and Halted says so).
func Run(ctx context.Context, cfg Config) (rep Report, retErr error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	switch {
	case cfg.Secrets == nil:
		return rep, errors.New("campaign: Secrets is required")
	case cfg.Recorder == nil:
		return rep, errors.New("campaign: Recorder is required")
	case len(cfg.Accounts) == 0:
		return rep, errors.New("campaign: at least one account is required")
	}
	m, err := prepare(cfg)
	if err != nil {
		return rep, err
	}
	guard, err := safety.NewGuard(cfg.Engagement, cfg.Scope, m, safety.GuardOptions{Now: cfg.Now})
	if err != nil {
		return rep, err
	}
	if err := guard.CheckOrigin(cfg.BaseURL); err != nil {
		return rep, fmt.Errorf("campaign: BaseURL refused: %w", err)
	}
	e, err := newEnv(cfg, m, guard, runTag(cfg.Engagement, cfg.Options.Seed))
	if err != nil {
		return rep, err
	}
	// A crash between MarkVerified and SaveRegression leaves a verified finding
	// with no regression. Demote those before doing anything else.
	stale, err := cfg.Recorder.ListVerifiedWithoutRegression(ctx, "")
	if err != nil {
		return rep, fmt.Errorf("campaign: check earlier findings for missing regressions: %w", err)
	}
	for _, f := range stale {
		if err := cfg.Recorder.SetFindingState(ctx, f.ID, verify.StateUnconfirmed, "regression missing (interrupted before save)", "aleef-campaign"); err != nil {
			return rep, fmt.Errorf("campaign: demote finding %s with no regression: %w", f.ID, err)
		}
		rep.RepairedUnregressed++
	}
	rep.Model = coverage(m)
	rep.NotModelled = append([]string(nil), m.NotModelled...)
	rep.PerOperation = map[string]OpCoverage{}
	for _, op := range m.Operations {
		rep.PerOperation[op.ID] = OpCoverage{Class: string(op.Class)}
	}

	// Money and notifying operations run only when the engagement's own rules
	// (safety.Allow) permit them; the generator never decides that itself.
	allowed := allowedOps(m, cfg.Engagement)

	var runErr error
	defer func() {
		// Whatever happened, compensate everything the campaign created.
		left, failed := e.sweep(ctx)
		rep.Orphans = mergeOrphans(rep.Orphans, left)
		if failed || len(rep.Orphans) > 0 {
			if rep.Halted == "" {
				rep.Halted = "cleanup failed"
			} else {
				rep.Halted += "; cleanup failed"
			}
		}
		st := guard.Stats()
		rep.Requests, rep.CleanupRequests = st.Requests, st.CleanupRequests
	}()

	// ---- generation fixture and generation
	genCleanup, gerr := e.generationFixture(ctx)
	var tests []generate.Test
	if gerr == nil {
		var genRep generate.Report
		tests, genRep, runErr = generate.GenerateWithReport(m, e.genFx, cfg.Accounts, generate.Options{
			Seed: cfg.Options.Seed, MaxTests: cfg.Options.MaxTests, Variations: cfg.Options.Variations,
			Workflow: cfg.Workflow, ReservedRoles: cfg.ReservedRoles, Limits: cfg.Limits,
			Catalogue: cfg.Options.Catalogue, AllowedOps: allowed,
		})
		rep.Generated = genRep
	} else {
		runErr = gerr
	}
	if genCleanup != nil {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
		orphans, cerr := genCleanup(cctx)
		cancel()
		if cerr != nil || len(orphans) > 0 {
			rep.Orphans = mergeOrphans(rep.Orphans, orphans)
		}
	}
	if runErr != nil {
		return rep, runErr
	}
	for _, id := range rep.Generated.SkippedOps {
		oc := rep.PerOperation[id]
		oc.Skipped = "class " + oc.Class
		rep.PerOperation[id] = oc
	}
	for id, t := range rep.Generated.NoFixtureOps {
		oc := rep.PerOperation[id]
		oc.Skipped = generate.NoFixtureReason(t)
		rep.PerOperation[id] = oc
	}

	runID, err := cfg.Recorder.CreateRun(ctx, "")
	if err != nil {
		return rep, fmt.Errorf("campaign: create run: %w", err)
	}
	rep.RunID = runID
	rep.Total = len(tests)

	// ---- verification
	haltFn := func() error {
		if st := guard.Stats(); st.Requests >= cfg.Engagement.MaxRequests {
			return errors.New("request budget exhausted")
		}
		return guard.Halt()
	}
	v := verify.New(e, cfg.Recorder, verify.Options{Reproductions: cfg.Options.Reproductions, RunID: runID, Halt: haltFn})
	stopReason := func() string {
		if ctx.Err() != nil {
			return "cancelled"
		}
		if err := haltFn(); err != nil {
			return err.Error()
		}
		return ""
	}
	byID := map[string]FindingSummary{}
	for i, t := range tests {
		op := t.Params["operation"]
		oc := rep.PerOperation[op]
		oc.Generated++
		rep.PerOperation[op] = oc
		out := TestOutcome{TestID: t.ID, Property: t.Property, Operation: op, State: StateNotExecuted}

		if rep.Halted == "" {
			if reason := stopReason(); reason != "" {
				rep.Halted = reason
			}
		}
		if rep.Halted != "" {
			rep.Tests = append(rep.Tests, out)
			continue
		}
		saved := true
		for _, tt := range []*generate.Test{&tests[i], t.OwnerControl, t.NegativeControl} {
			if tt == nil {
				continue
			}
			if err := cfg.Recorder.SaveTest(ctx, runID, *tt); err != nil {
				saved = false
				runErr = fmt.Errorf("campaign: save test: %w", err)
				break
			}
		}
		if !saved {
			rep.Halted = "recording error"
			rep.Tests = append(rep.Tests, out)
			continue
		}
		before := e.freshCount()
		verdict, verr := v.Verify(ctx, t)
		out.Executed = e.freshCount() > before
		out.State, out.Reason, out.EvidenceHash, out.Reproductions = verdict.State, verdict.Reason, verdict.EvidenceHash, verdict.Reproductions
		out.OwnerControl, out.NegativeControl = verdict.OwnerControl, verdict.NegativeControl
		rep.Orphans = mergeOrphans(rep.Orphans, verdict.Orphans)
		if verr != nil {
			runErr = fmt.Errorf("campaign: verify %s: %w", t.ID, verr)
			out.State, out.Reason = verify.StateUnconfirmed, "recording error"
			rep.Halted = "recording error"
		} else if strings.HasPrefix(verdict.Reason, "halted:") || verdict.Reason == "interrupted" {
			if r := stopReason(); r != "" {
				rep.Halted = r
			} else {
				rep.Halted = strings.TrimPrefix(verdict.Reason, "halted: ")
			}
		}
		if verr == nil && verdict.State == verify.StateVerified {
			// A verified finding without a saved regression is not allowed to
			// stay verified: save it now or demote the finding.
			detached := context.WithoutCancel(ctx)
			rid, rerr := saveRegression(detached, cfg.Recorder, verdict.FindingID, t)
			if rerr == nil {
				out.RegressionID = rid
			} else {
				const reason = "regression could not be saved"
				rep.RegressionFailed++
				out.State, out.Reason, out.EvidenceHash = verify.StateUnconfirmed, reason, ""
				if serr := cfg.Recorder.SetFindingState(detached, verdict.FindingID, verify.StateUnconfirmed, reason, "aleef-campaign"); serr != nil {
					runErr = fmt.Errorf("campaign: demote finding %s after regression failure: %w", verdict.FindingID, serr)
					rep.Halted = "recording error"
				}
			}
		}
		if !out.Executed {
			out.State = StateNotExecuted
		}
		rep.Tests = append(rep.Tests, out)
		if out.Reproductions > 0 || out.State == verify.StateVerified {
			byID[t.ID] = FindingSummary{FindingID: verdict.FindingID, TestID: t.ID, Property: t.Property, Operation: op,
				State: out.State, Reason: out.Reason, EvidenceHash: out.EvidenceHash, RegressionID: out.RegressionID,
				OwnerControl: out.OwnerControl, NegativeControl: out.NegativeControl}
		}
	}

	tally(&rep)
	for _, o := range rep.Tests {
		if s, ok := byID[o.TestID]; ok {
			rep.Findings = append(rep.Findings, s)
		}
	}
	return rep, runErr
}

// allowedOps lists the money and notifying operations the engagement's own
// declarations (safety.Allow) permit to run. Nothing is allowed by default.
func allowedOps(m model.Model, e safety.Engagement) map[string]bool {
	allowed := map[string]bool{}
	for _, op := range m.Operations {
		c := safety.FromOpClass(op.Class)
		if (c == safety.ClassMoney || c == safety.ClassNotifying) && safety.Allow(c, op, e) == nil {
			allowed[op.ID] = true
		}
	}
	return allowed
}

// tally derives every count from rep.Tests so they cannot disagree.
func tally(rep *Report) {
	for _, o := range rep.Tests {
		oc := rep.PerOperation[o.Operation]
		if !o.Executed {
			rep.NotExecuted++
			oc.NotExecuted++
			rep.PerOperation[o.Operation] = oc
			continue
		}
		rep.Executed++
		oc.Executed++
		if o.Reproductions > 0 || o.State == verify.StateVerified {
			oc.Findings++
		}
		switch o.State {
		case verify.StateClean:
			rep.Clean++
		case verify.StateVerified:
			rep.Verified++
			oc.Verified++
		case verify.StateRejected:
			rep.Rejected++
		case verify.StateUnconfirmed:
			if strings.Contains(o.Reason, "inconclusive") {
				rep.Inconclusive++
			} else {
				rep.Unconfirmed++
			}
		}
		if o.State == verify.StateCandidate || o.Reproductions > 0 {
			rep.ReachedCandidate++
		}
		rep.PerOperation[o.Operation] = oc
	}
}

// saveRegression exports and stores the regression of a verified finding and
// returns its id.
func saveRegression(ctx context.Context, rec Recorder, findingID string, t generate.Test) (string, error) {
	if findingID == "" {
		return "", errors.New("campaign: verified finding has no id")
	}
	f, err := rec.GetFinding(ctx, findingID)
	if err != nil {
		return "", err
	}
	seq, err := rec.NextRegressionSeq(ctx)
	if err != nil {
		return "", err
	}
	reg, err := export.ToRegression(f, t, seq)
	if err != nil {
		return "", err
	}
	if err := rec.SaveRegression(ctx, findingID, reg.Bundle.RegressionID, reg.BundleJSON, reg.ScenarioYAML, reg.YAMLNote); err != nil {
		return "", err
	}
	return reg.Bundle.RegressionID, nil
}
