// Package exec runs generated ALEEF tests through the API BAS runner and
// turns the runner's report into a verdict.
//
// It owns three things the runner does not: a StateReader that reads objects
// through the application model as their owners (UATState), a Resetter that
// undoes only what ALEEF created (CompensatingReset), and the oracle layer
// that decides finding yes / no / inconclusive from the typed property
// template (see property.OracleKind) instead of the runner's own grade.
//
// The package is on the executing side: it must not import the benchmark
// bank, its sealed data or the bench harness.
package exec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/audspect/bas/internal/aleef/generate"
	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/property"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/runner"
)

// Finding is the outcome of one test's oracle.
type Finding string

const (
	FindingYes          Finding = "yes"
	FindingNo           Finding = "no"
	FindingInconclusive Finding = "inconclusive"
)

// Verdict is the oracle's decision for one test.
type Verdict struct {
	Finding Finding
	// Reason says why, in words that never contain tokens or response bodies.
	Reason string
	Oracle property.OracleKind
}

// Result is a run's runner report and the verdict computed from it.
type Result struct {
	Report  runner.Report
	Verdict Verdict
}

// Config holds the executor's dependencies.
type Config struct {
	BaseURL string
	Fixture fixture.Fixture
	Secrets runner.SecretResolver
	// Created are the objects BuildFixture made; they are known to UATState
	// and compensated by Cleanup.
	Created []model.CreatedObject
	// Doer sends the state-reader and cleanup requests. Nil uses HTTP.
	Doer  model.Doer
	Model model.Model
	// HTTP is the runner's client. Nil uses a client with a 10 second timeout.
	HTTP *http.Client
	// ReadOperation optionally names the Read operation UATState uses.
	ReadOperation string
	// StateExtra optionally adds an enumerating state adapter whose records
	// are merged into every snapshot (UATState cannot see records the attack
	// creates under ids it does not know).
	StateExtra runner.StateReader
}

// Executor runs tests one at a time against one target.
type Executor struct {
	cfg   Config
	state *UATState
	reset *CompensatingReset

	mu sync.Mutex // one run at a time: the state recorder is per run
}

// checkBaseURL is the interim target guard: only loopback targets are
// allowed. The engagement gate replaces this function.
func checkBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("exec: BaseURL must be an absolute http or https URL")
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("exec: target host %q is not loopback; non-loopback targets need the engagement gate", host)
}

// New validates the configuration and returns an executor.
func New(cfg Config) (*Executor, error) {
	if err := checkBaseURL(cfg.BaseURL); err != nil {
		return nil, err
	}
	if cfg.Secrets == nil {
		return nil, errors.New("exec: Secrets is required")
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	doer := cfg.Doer
	if doer == nil {
		doer = cfg.HTTP
	}
	state, err := newUATState(cfg, doer)
	if err != nil {
		return nil, err
	}
	return &Executor{cfg: cfg, state: state, reset: newCompensatingReset(cfg, doer)}, nil
}

// State returns the executor's UATState.
func (e *Executor) State() *UATState { return e.state }

// Resetter returns the executor's CompensatingReset.
func (e *Executor) Resetter() *CompensatingReset { return e.reset }

// Track registers an object created during a run with both the state reader
// and the compensating reset.
func (e *Executor) Track(o model.CreatedObject) {
	e.state.Track(o)
	e.reset.Track(o)
}

// Cleanup compensates everything ALEEF created. Call it at the end of a
// campaign.
func (e *Executor) Cleanup(ctx context.Context) error { return e.reset.Cleanup(ctx) }

// Orphans lists objects that could not be compensated.
func (e *Executor) Orphans() []model.CreatedObject { return e.reset.Orphans() }

// Run executes one generated test through a fresh runner and returns the
// runner report and the oracle verdict. A test whose scenario does not
// validate is refused before any request is sent.
func (e *Executor) Run(ctx context.Context, t generate.Test) (Result, error) {
	if err := t.Scenario.Validate(); err != nil {
		return Result{}, fmt.Errorf("exec: refusing test %s: %w", t.ID, err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	rec := &recorder{inner: e.state}
	rcfg := runner.Config{
		BaseURL: e.cfg.BaseURL,
		Fixture: e.cfg.Fixture,
		Secrets: e.cfg.Secrets,
		State:   rec,
		HTTP:    e.cfg.HTTP,
	}
	if t.Scenario.SideEffectClass == "STATE_CHANGE_SANDBOX" {
		rcfg.Reset = e.reset
	}
	r, err := runner.New(rcfg)
	if err != nil {
		return Result{}, err
	}
	rep, err := r.Run(ctx, t.Scenario)
	if err != nil {
		return Result{Report: rep}, err
	}
	changed, known := rec.diff()
	v := e.judge(t, rep, stateEvidence{known: known, changed: changed})
	return Result{Report: rep, Verdict: v}, nil
}
