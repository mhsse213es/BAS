package campaign

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/audspect/bas/internal/aleef/exec"
	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/safety"
	"github.com/audspect/bas/internal/apibas/fixture"
)

// hostDoer points the placeholder origin of setup requests (see
// model.BuildFixture) at the engagement's base URL. The wrapped Doer is the
// guarded client, so the guard sees the real origin of every request.
type hostDoer struct {
	inner  model.Doer
	scheme string
	host   string
	prefix string
}

func (d hostDoer) Do(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.URL.Scheme, r2.URL.Host = d.scheme, d.host
	r2.URL.Path = d.prefix + r2.URL.Path
	r2.URL.RawPath = ""
	r2.Host = d.host
	return d.inner.Do(r2)
}

// run is one fresh environment: one executor, one cleanup.
type run struct {
	cleanup func(context.Context) ([]model.CreatedObject, error)
	done    bool
	orphans []model.CreatedObject
}

// env implements verify.Env. Every Fresh call builds a new fixture on the
// target and a new executor; nothing is reused between runs.
type env struct {
	cfg     Config
	m       model.Model
	guard   *safety.Guard
	tag     string
	base    http.RoundTripper
	timeout time.Duration
	setup   model.Doer

	// genFx, genCreated, genIDs and haveGen are written once by
	// generationFixture, before the first Fresh call and before any verifier
	// runs, and are read-only afterwards; they need no lock.
	genFx      fixture.Fixture
	genCreated []model.CreatedObject
	genIDs     []string
	haveGen    bool

	mu     sync.Mutex
	runs   []*run
	fresh  int // successful Fresh calls
	failed int
}

func newEnv(cfg Config, m model.Model, g *safety.Guard, tag string) (*env, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("campaign: BaseURL is not a valid http(s) URL")
	}
	e := &env{cfg: cfg, m: m, guard: g, tag: tag, base: http.DefaultTransport, timeout: 10 * time.Second}
	if cfg.HTTP != nil {
		if cfg.HTTP.Transport != nil {
			e.base = cfg.HTTP.Transport
		}
		if cfg.HTTP.Timeout > 0 {
			e.timeout = cfg.HTTP.Timeout
		}
	}
	guarded, err := g.WrapDoer(&http.Client{Transport: e.base, Timeout: e.timeout})
	if err != nil {
		return nil, err
	}
	e.setup = hostDoer{inner: guarded, scheme: u.Scheme, host: u.Host, prefix: strings.TrimRight(u.Path, "/")}
	return e, nil
}

func ids(c []model.CreatedObject) []string {
	out := make([]string, len(c))
	for i, o := range c {
		out[i] = o.ID
	}
	return out
}

// build creates one fixture and one executor. When aliasing is on (a
// generation fixture exists) the executor works in the generation namespace.
func (e *env) build(ctx context.Context, aliasing bool) (*exec.Executor, func(context.Context) ([]model.CreatedObject, error), fixture.Fixture, []model.CreatedObject, error) {
	fx, created, berr := model.BuildFixture(ctx, e.m, e.cfg.Accounts, e.cfg.Setup, e.setup, e.cfg.Secrets, e.tag)
	ecfg := exec.Config{
		BaseURL: e.cfg.BaseURL, Model: e.m, Guard: e.guard, Secrets: e.cfg.Secrets,
		Fixture: fx, Created: created,
	}
	rt := e.base
	if aliasing && berr == nil && len(created) == len(e.genCreated) {
		var art http.RoundTripper
		art, berr = newAlias(e.base, e.genIDs, ids(created), e.m)
		if berr == nil {
			rt = art
			if _, ok := rt.(aliasRT); ok {
				ecfg.Fixture, ecfg.Created = e.genFx, e.genCreated
			}
		}
	}
	// exec guards this client's transport itself; it must not be guarded twice
	// or every request would be counted twice against the budget.
	tracker := newTrackRT(rt, e.cfg, e.m)
	if al, ok := rt.(aliasRT); ok {
		tracker.learn = al.learn
	}
	for _, f := range []fixture.Fixture{fx, ecfg.Fixture} {
		for _, o := range f.Objects {
			tracker.markKnown(o.ID)
		}
	}
	ecfg.HTTP = &http.Client{Transport: tracker, Timeout: e.timeout}
	ex, xerr := exec.New(ecfg)
	if xerr != nil {
		return nil, nil, fx, created, xerr
	}
	tracker.setTrack(ex.Track)
	r := &run{}
	r.cleanup = func(cctx context.Context) ([]model.CreatedObject, error) {
		err := ex.Cleanup(cctx)
		orphans := ex.Orphans()
		e.mu.Lock()
		r.done = err == nil && len(orphans) == 0
		r.orphans = orphans
		e.mu.Unlock()
		return orphans, err
	}
	e.mu.Lock()
	e.runs = append(e.runs, r)
	e.mu.Unlock()
	if berr != nil {
		// Partial fixture: nothing can run, but what was created is cleaned.
		return nil, r.cleanup, fx, created, berr
	}
	return ex, r.cleanup, fx, created, nil
}

// Fresh implements verify.Env.
func (e *env) Fresh(ctx context.Context) (*exec.Executor, func(context.Context) ([]model.CreatedObject, error), error) {
	ex, cleanup, _, _, err := e.build(ctx, e.haveGen)
	e.mu.Lock()
	if err != nil {
		e.failed++
	} else {
		e.fresh++
	}
	e.mu.Unlock()
	if err != nil {
		return nil, cleanup, fmt.Errorf("campaign: fresh environment: %w", err)
	}
	return ex, cleanup, nil
}

func (e *env) freshCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.fresh
}

// generationFixture builds the fixture tests are generated from. The caller
// cleans it up with the returned func.
func (e *env) generationFixture(ctx context.Context) (func(context.Context) ([]model.CreatedObject, error), error) {
	_, cleanup, fx, created, err := e.build(ctx, false)
	if err != nil {
		return cleanup, fmt.Errorf("campaign: generation fixture: %w", err)
	}
	e.genFx, e.genCreated, e.genIDs, e.haveGen = fx, created, ids(created), true
	return cleanup, nil
}

// sweep retries every cleanup that has not succeeded and returns what is still
// left behind.
func (e *env) sweep(ctx context.Context) ([]model.CreatedObject, bool) {
	e.mu.Lock()
	var pending []*run
	for _, r := range e.runs {
		if !r.done {
			pending = append(pending, r)
		}
	}
	e.mu.Unlock()
	var left []model.CreatedObject
	failed := false
	for _, r := range pending {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
		orphans, err := r.cleanup(cctx)
		cancel()
		if err != nil || len(orphans) > 0 {
			failed = true
			left = mergeOrphans(left, orphans)
		}
	}
	return left, failed
}

func mergeOrphans(a, b []model.CreatedObject) []model.CreatedObject {
	out := append([]model.CreatedObject(nil), a...)
	for _, o := range b {
		dup := false
		for _, x := range out {
			if x.ID == o.ID && x.Operation == o.Operation {
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
