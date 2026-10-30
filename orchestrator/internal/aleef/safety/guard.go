package safety

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/targetscope"
)

// GuardOptions tune a Guard. The zero value is usable.
type GuardOptions struct {
	// Now is the clock. Nil uses time.Now.
	Now func() time.Time
	// Sleep waits for d or until ctx is done. Nil uses a real timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// LatencyLimit trips the breaker when three consecutive responses take
	// longer. Zero disables the latency rule.
	LatencyLimit time.Duration
}

// Stats is a snapshot of a Guard's counters.
type Stats struct {
	Requests        int // non-cleanup requests admitted (counted against the budget)
	CleanupRequests int
	Refused         int
	InFlight        int
	Halted          bool
	HaltReason      string
	Stopped         bool
}

type cleanupKey struct{}

// WithCleanup marks ctx as carrying a compensation request. Such requests are
// exempt from the rate limit, concurrency cap, budget, breaker and kill
// switch, and from nothing else: origin, window and class are still enforced.
func WithCleanup(ctx context.Context) context.Context {
	return context.WithValue(ctx, cleanupKey{}, true)
}

// IsCleanup reports whether ctx was marked with WithCleanup.
func IsCleanup(ctx context.Context) bool {
	v, _ := ctx.Value(cleanupKey{}).(bool)
	return v
}

// Guard enforces an engagement on every outgoing request. It is safe for
// concurrent use.
type Guard struct {
	e Engagement
	m model.Model
	// extra are the engagement's own routes (its Classes, sorted by signature). They are matched against
	// every request in addition to the model, so a route the administrator classified is judged by that
	// class even when the run document leaves it out or covers it with a looser parameter route.
	extra   []model.Operation
	origins map[string]bool
	now     func() time.Time
	sleep   func(ctx context.Context, d time.Duration) error
	latency time.Duration
	sem     chan struct{}

	mu        sync.Mutex
	requests  int
	cleanups  int
	refused   int
	inflight  int
	stopped   bool
	stopCh    chan struct{}
	haltErr   error
	next      time.Time // earliest start of the next rate slot
	interval  time.Duration
	consec5xx int
	consecLat int
	nextID    uint64
	cancels   map[uint64]context.CancelFunc
}

// NewGuard validates the engagement against every host and the scope at the
// current time and returns a Guard for it. m classifies the requests.
func NewGuard(e Engagement, scope *targetscope.TargetScopeImport, m model.Model, opts GuardOptions) (*Guard, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	sleep := opts.Sleep
	if sleep == nil {
		sleep = realSleep
	}
	g := &Guard{
		e: e, m: m, origins: map[string]bool{}, now: now, sleep: sleep, latency: opts.LatencyLimit,
		stopCh: make(chan struct{}), cancels: map[uint64]context.CancelFunc{},
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	for _, h := range e.Hosts {
		if err := e.Authorize(h, scope, now()); err != nil {
			return nil, err
		}
		n, _ := NormalizeOrigin(h)
		g.origins[n] = true
	}
	sigs := make([]string, 0, len(e.Classes))
	for sig := range e.Classes {
		sigs = append(sigs, sig)
	}
	sort.Strings(sigs)
	for _, sig := range sigs {
		i := strings.IndexByte(sig, ' ') // Validate guarantees the canonical "METHOD /path" form
		g.extra = append(g.extra, model.Operation{ID: sig, Method: sig[:i], Path: sig[i+1:], Class: model.OpClass(e.Classes[sig])})
	}
	g.sem = make(chan struct{}, e.MaxConcurrent)
	g.interval = time.Duration(float64(time.Second) / e.RPS)
	return g, nil
}

func realSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Engagement returns the engagement the guard enforces.
func (g *Guard) Engagement() Engagement { return g.e }

// CheckOrigin reports whether the origin of rawURL (scheme, host and port;
// any path is ignored) is exactly an engagement host. It is the BaseURL check.
func (g *Guard) CheckOrigin(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || rawURL == "" {
		return fmt.Errorf("%w: not a valid URL", ErrOriginRefused)
	}
	return g.checkURLOrigin(u)
}

func (g *Guard) checkURLOrigin(u *url.URL) error {
	o, err := originOf(u, false)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOriginRefused, err)
	}
	if !g.origins[o] {
		return fmt.Errorf("%w: %s is not an engagement host", ErrNotAuthorized, o)
	}
	return nil
}

// Stop is the kill switch: every later non-cleanup request is refused with
// ErrStopped and every in-flight non-cleanup request is cancelled.
func (g *Guard) Stop() {
	g.mu.Lock()
	if !g.stopped {
		g.stopped = true
		close(g.stopCh)
	}
	cancels := make([]context.CancelFunc, 0, len(g.cancels))
	for _, c := range g.cancels {
		cancels = append(cancels, c)
	}
	g.mu.Unlock()
	for _, c := range cancels {
		c()
	}
}

// trip halts the run (first reason wins).
func (g *Guard) trip(reason string) {
	g.mu.Lock()
	if g.haltErr == nil {
		g.haltErr = fmt.Errorf("%w: %s", ErrHalted, reason)
	}
	g.mu.Unlock()
}

// Halt returns the reason the run must stop, or nil. It is meant for
// verify.Options.Halt.
func (g *Guard) Halt() error {
	g.mu.Lock()
	stopped, h := g.stopped, g.haltErr
	g.mu.Unlock()
	if stopped {
		return ErrStopped
	}
	if h != nil {
		return h
	}
	return g.e.InWindow(g.now())
}

// Stats returns a snapshot of the counters.
func (g *Guard) Stats() Stats {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := Stats{Requests: g.requests, CleanupRequests: g.cleanups, Refused: g.refused, InFlight: g.inflight, Stopped: g.stopped}
	if g.haltErr != nil {
		s.Halted, s.HaltReason = true, g.haltErr.Error()
	}
	return s
}

// Transport wraps next so that every request passes the guard first.
func (g *Guard) Transport(next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return guardRT{g: g, next: next}
}

type guardRT struct {
	g    *Guard
	next http.RoundTripper
}

func (t guardRT) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.g.do(r, t.next.RoundTrip)
}

// WrapDoer returns a guarded copy of d. Only an exactly *http.Client is
// accepted: it is rebuilt with a guarded Transport and a redirect policy that
// refuses every redirect, so nothing is ever sent before it is checked and a
// redirect target is never requested. Any other Doer cannot be guarded (it
// could send first and be checked after, or follow redirects itself) and is an
// error.
func (g *Guard) WrapDoer(d model.Doer) (model.Doer, error) {
	c, ok := d.(*http.Client)
	if !ok || c == nil {
		return nil, fmt.Errorf("safety: only a *http.Client can be guarded, got %T", d)
	}
	cc := *c
	cc.Transport = g.Transport(c.Transport)
	cc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cc, nil
}

var overrideHeaders = []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"}

// effectiveMethods lists the request's method and every method a header or
// the _method query parameter could turn it into.
func effectiveMethods(r *http.Request) []string {
	m := strings.ToUpper(r.Method)
	if m == "" {
		m = http.MethodGet
	}
	out := []string{m}
	add := func(v string) {
		for _, p := range strings.Split(v, ",") {
			p = strings.ToUpper(strings.TrimSpace(p))
			if p == "" {
				continue
			}
			dup := false
			for _, o := range out {
				if o == p {
					dup = true
				}
			}
			if !dup {
				out = append(out, p)
			}
		}
	}
	// Header maps may hold non-canonical keys (written directly); the wire
	// carries them as sent, so compare keys case-insensitively.
	for k, vs := range r.Header {
		for _, h := range overrideHeaders {
			if strings.EqualFold(k, h) {
				for _, v := range vs {
					add(v)
				}
			}
		}
	}
	if r.URL != nil {
		for k, vs := range r.URL.Query() {
			if strings.EqualFold(k, "_method") {
				for _, v := range vs {
					add(v)
				}
			}
		}
	}
	return out
}

// pathAcceptable refuses paths whose meaning could differ between this check
// and the server: dot segments, empty segments, backslashes, encoded slashes
// and control characters.
func pathAcceptable(u *url.URL) bool {
	p := u.Path
	if p == "" || p[0] != '/' || strings.Contains(p, `\`) {
		return false
	}
	// Forms a server may decode, strip or route differently from this check:
	// matrix parameters, double encoding, encoded dots, slashes, backslashes,
	// spaces and NUL.
	if strings.Contains(p, ";") {
		return false
	}
	esc := strings.ToLower(u.EscapedPath())
	for _, bad := range []string{"%25", "%2e", "%2f", "%5c", "%20", "%00", "%3b"} {
		if strings.Contains(esc, bad) {
			return false
		}
	}
	for _, c := range p {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	segs := strings.Split(p[1:], "/")
	for i, s := range segs {
		if s == "." || s == ".." || s != strings.TrimSpace(s) {
			return false
		}
		if s == "" && !(i == len(segs)-1 && len(segs) > 1) && p != "/" {
			return false
		}
	}
	return true
}

func pathMatchesFold(opPath, concrete string) bool {
	a := strings.Split(strings.Trim(opPath, "/"), "/")
	b := strings.Split(strings.Trim(concrete, "/"), "/")
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.HasPrefix(a[i], "{") && strings.HasSuffix(a[i], "}") {
			if b[i] == "" {
				return false
			}
			continue
		}
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
}

// classify finds the operations a request could be and checks every one of
// them against the engagement.
func (g *Guard) classify(r *http.Request) error {
	if !pathAcceptable(r.URL) {
		return fmt.Errorf("%w: request path is not acceptable", ErrClassRefused)
	}
	for _, method := range effectiveMethods(r) {
		ops := g.m.Match(method, r.URL.Path)
		if len(ops) == 0 {
			return fmt.Errorf("%w: %s request is not an operation of the model (unknown class)", ErrClassRefused, method)
		}
		// Matching is case-sensitive. A path that would match another route if
		// case were ignored may reach that route on a case-insensitive server.
		for _, op := range g.m.Operations {
			if strings.EqualFold(op.Method, method) && pathMatchesFold(op.Path, r.URL.Path) && !model.PathMatches(op.Path, r.URL.Path) {
				return fmt.Errorf("%w: path matches operation %q only when case is ignored", ErrClassRefused, op.ID)
			}
		}
		// The engagement's own routes are candidates too: a literal route it classifies beats a looser
		// parameter route in the document, and one the document omits is still enforced.
		for _, op := range g.extra {
			if !strings.EqualFold(op.Method, method) {
				continue
			}
			if model.PathMatches(op.Path, r.URL.Path) {
				ops = append(ops, op)
			} else if pathMatchesFold(op.Path, r.URL.Path) {
				return fmt.Errorf("%w: path matches engagement route %q only when case is ignored", ErrClassRefused, op.ID)
			}
		}
		// Every matching operation must pass; the most restrictive is checked
		// first so its refusal is the one reported.
		worst := ops[0]
		for _, op := range ops[1:] {
			if rank(FromOpClass(op.Class)) > rank(FromOpClass(worst.Class)) {
				worst = op
			}
		}
		if err := Allow(FromOpClass(worst.Class), worst, g.e); err != nil {
			return err
		}
		for _, op := range ops {
			if err := Allow(FromOpClass(op.Class), op, g.e); err != nil {
				return err
			}
		}
	}
	return nil
}

func (g *Guard) refusal(err error) error {
	g.mu.Lock()
	g.refused++
	g.mu.Unlock()
	return err
}

// preflight performs the checks that apply to every request, cleanup or not.
func (g *Guard) preflight(r *http.Request) error {
	if r.Response != nil {
		return ErrRedirect
	}
	if r.URL == nil {
		return fmt.Errorf("%w: request has no URL", ErrOriginRefused)
	}
	if err := g.checkURLOrigin(r.URL); err != nil {
		return err
	}
	if r.Host != "" {
		hu := &url.URL{Scheme: r.URL.Scheme, Host: r.Host}
		a, errA := originOf(hu, false)
		b, errB := originOf(r.URL, false)
		if errA != nil || errB != nil || a != b {
			return fmt.Errorf("%w: Host header differs from the request URL", ErrOriginRefused)
		}
	}
	if err := g.e.InWindow(g.now()); err != nil {
		return err
	}
	return g.classify(r)
}

// gate returns the error that stops a non-cleanup request.
func (g *Guard) gate() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopped {
		return ErrStopped
	}
	return g.haltErr
}

func (g *Guard) do(r *http.Request, send func(*http.Request) (*http.Response, error)) (*http.Response, error) {
	cleanup := IsCleanup(r.Context())
	if err := g.preflight(r); err != nil {
		return nil, g.refusal(err)
	}
	if cleanup {
		g.mu.Lock()
		g.cleanups++
		g.mu.Unlock()
		resp, err := send(r)
		return resp, err
	}
	if err := g.gate(); err != nil {
		return nil, g.refusal(err)
	}
	g.mu.Lock()
	if g.requests >= g.e.MaxRequests {
		g.mu.Unlock()
		return nil, g.refusal(fmt.Errorf("%w: %d requests", ErrBudgetExhausted, g.e.MaxRequests))
	}
	g.requests++
	// rate slot: one request per interval, reserved under the lock
	now := g.now()
	slot := g.next
	if slot.Before(now) {
		slot = now
	}
	g.next = slot.Add(g.interval)
	wait := slot.Sub(now)
	g.mu.Unlock()

	ctx, cancel := context.WithCancel(r.Context())
	g.mu.Lock()
	g.nextID++
	id := g.nextID
	g.cancels[id] = cancel
	stopped := g.stopped
	g.mu.Unlock()
	release := func() {
		g.mu.Lock()
		delete(g.cancels, id)
		g.mu.Unlock()
		cancel()
	}
	if stopped {
		release()
		return nil, g.refusal(ErrStopped)
	}

	if wait > 0 {
		if err := g.sleep(ctx, wait); err != nil {
			release()
			return nil, g.refusal(g.stopOr(err))
		}
	}
	select {
	case g.sem <- struct{}{}:
	case <-ctx.Done():
		release()
		return nil, g.refusal(g.stopOr(ctx.Err()))
	case <-g.stopCh:
		release()
		return nil, g.refusal(ErrStopped)
	}
	// conditions may have changed while waiting
	if err := g.gate(); err != nil {
		<-g.sem
		release()
		return nil, g.refusal(err)
	}
	if err := g.e.InWindow(g.now()); err != nil {
		<-g.sem
		release()
		return nil, g.refusal(err)
	}
	g.mu.Lock()
	g.inflight++
	g.mu.Unlock()

	start := g.now()
	resp, err := send(r.WithContext(ctx))
	elapsed := g.now().Sub(start)

	g.mu.Lock()
	g.inflight--
	g.mu.Unlock()
	<-g.sem

	g.observe(ctx, resp, err, elapsed)
	if err != nil {
		release()
		return nil, g.stopOr(err)
	}
	resp.Body = &releaseBody{ReadCloser: resp.Body, release: release}
	return resp, nil
}

// stopOr reports ErrStopped when the kill switch caused err.
func (g *Guard) stopOr(err error) error {
	g.mu.Lock()
	stopped := g.stopped
	g.mu.Unlock()
	if stopped {
		return ErrStopped
	}
	return err
}

// observe feeds the circuit breaker.
func (g *Guard) observe(ctx context.Context, resp *http.Response, err error, elapsed time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	trip := func(reason string) {
		if g.haltErr == nil {
			g.haltErr = fmt.Errorf("%w: %s", ErrHalted, reason)
		}
	}
	if err != nil {
		if ctx.Err() == nil { // not a cancellation: a transport failure counts like a 5xx
			g.consec5xx++
			if g.consec5xx >= 3 {
				trip("three consecutive failures")
			}
		}
		return
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		trip("received 429")
	case resp.StatusCode >= 500:
		g.consec5xx++
		if g.consec5xx >= 3 {
			trip("three consecutive 5xx responses")
		}
	default:
		g.consec5xx = 0
	}
	if g.latency > 0 {
		if elapsed > g.latency {
			g.consecLat++
			if g.consecLat >= 3 {
				trip("latency above the limit for three consecutive requests")
			}
		} else {
			g.consecLat = 0
		}
	}
}

type releaseBody struct {
	io.ReadCloser
	release func()
	once    sync.Once
}

func (b *releaseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}
