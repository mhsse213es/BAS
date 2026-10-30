package safety

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/audspect/bas/internal/aleef/model"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func resp(code int) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}
}

type fakeClock struct {
	mu       sync.Mutex
	t        time.Time
	sleeps   []time.Duration
	advances bool
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}
func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	c.sleeps = append(c.sleeps, d)
	if c.advances {
		c.t = c.t.Add(d)
	}
	c.mu.Unlock()
	return nil
}

func guardModel() model.Model {
	return model.Model{Operations: []model.Operation{
		{ID: "getItem", Method: "GET", Path: "/api/items/{id}", Class: model.ClassRead},
		{ID: "listItems", Method: "GET", Path: "/api/items", Class: model.ClassRead},
		{ID: "delItem", Method: "DELETE", Path: "/api/items/{id}", Class: model.ClassReversible},
		{ID: "getPay", Method: "GET", Path: "/api/pay", Class: model.ClassRead},
		{ID: "pay", Method: "POST", Path: "/api/pay", Class: model.ClassMoney},
		{ID: "xAny", Method: "GET", Path: "/api/x/{a}", Class: model.ClassRead},
		{ID: "xSpecial", Method: "GET", Path: "/api/x/special", Class: model.ClassMoney},
		{ID: "mystery", Method: "GET", Path: "/api/mystery", Class: model.ClassUnknown},
	}}
}

func newTestGuard(t *testing.T, mut func(*Engagement), opts GuardOptions) (*Guard, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: t0}
	e := uatEngagement()
	e.RPS = 1e6
	e.MaxRequests = 1000
	if mut != nil {
		mut(&e)
	}
	if opts.Now == nil {
		opts.Now = clk.Now
	}
	if opts.Sleep == nil {
		opts.Sleep = clk.Sleep
	}
	g, err := NewGuard(e, uatScope(), guardModel(), opts)
	if err != nil {
		t.Fatal(err)
	}
	return g, clk
}

func get(t *testing.T, ctx context.Context, method, url string) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func okTransport(calls *int32) http.RoundTripper {
	return rtFunc(func(*http.Request) (*http.Response, error) {
		atomic.AddInt32(calls, 1)
		return resp(200), nil
	})
}

const itemURL = uatOrigin + "/api/items/1"

func TestGuardAllowsListedRead(t *testing.T) {
	g, _ := newTestGuard(t, nil, GuardOptions{})
	var calls int32
	rt := g.Transport(okTransport(&calls))
	r, err := rt.RoundTrip(get(t, context.Background(), "GET", itemURL+"?x=1"))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestGuardRefusesUnlistedOriginAndUserinfo(t *testing.T) {
	g, _ := newTestGuard(t, nil, GuardOptions{})
	var calls int32
	rt := g.Transport(okTransport(&calls))
	for _, u := range []string{
		"https://evil.example:8443/api/items/1",
		"http://listed@evil.example/api/items/1",
		"https://listed@uat.bank.example:8443/api/items/1",
		"http://uat.bank.example:8443/api/items/1",
		"https://uat.bank.example/api/items/1",
		"https://uat.bank.example:9443/api/items/1",
		"https://uat.bank.example.evil.example:8443/api/items/1",
	} {
		_, err := rt.RoundTrip(get(t, context.Background(), "GET", u))
		if !errors.Is(err, ErrOriginRefused) && !errors.Is(err, ErrNotAuthorized) {
			t.Fatalf("%s: got %v", u, err)
		}
	}
	// case-insensitive host is accepted
	r, err := rt.RoundTrip(get(t, context.Background(), "GET", "https://UAT.BANK.EXAMPLE:8443/api/items/1"))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	// a Host header that differs from the URL host is refused
	rq := get(t, context.Background(), "GET", itemURL)
	rq.Host = "evil.example"
	if _, err := rt.RoundTrip(rq); err == nil {
		t.Fatal("host header override accepted")
	}
	if calls != 1 {
		t.Fatalf("a refused request reached the network: calls=%d", calls)
	}
}

func TestGuardRefusesMethodOverrideToMoneyRoute(t *testing.T) {
	g, _ := newTestGuard(t, nil, GuardOptions{})
	var calls int32
	rt := g.Transport(okTransport(&calls))
	plain := get(t, context.Background(), "GET", uatOrigin+"/api/pay")
	r, err := rt.RoundTrip(plain)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	for _, h := range []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"} {
		rq := get(t, context.Background(), "GET", uatOrigin+"/api/pay")
		rq.Header.Set(h, "post")
		if _, err := rt.RoundTrip(rq); !errors.Is(err, ErrClassRefused) {
			t.Fatalf("%s: got %v", h, err)
		}
	}
	rq := get(t, context.Background(), "GET", uatOrigin+"/api/pay?_method=POST")
	if _, err := rt.RoundTrip(rq); !errors.Is(err, ErrClassRefused) {
		t.Fatalf("_method: got %v", err)
	}
	// real money method with an override down to a read is still money
	rq = get(t, context.Background(), "POST", uatOrigin+"/api/pay")
	rq.Header.Set("X-HTTP-Method-Override", "GET")
	if _, err := rt.RoundTrip(rq); !errors.Is(err, ErrClassRefused) {
		t.Fatalf("downgrade override: got %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestGuardRefusesUnmatchedPath(t *testing.T) {
	g, _ := newTestGuard(t, nil, GuardOptions{})
	var calls int32
	rt := g.Transport(okTransport(&calls))
	for _, p := range []string{
		"/api/secret", "/", "/api/items/1/extra", "/api/mystery", "/API/items/1",
		"/api/items/../pay", "/api/items/./1", "/api//items/1", "/api/items/%2e%2e", "/api%5citems/1",
	} {
		_, err := rt.RoundTrip(get(t, context.Background(), "GET", uatOrigin+p))
		if !errors.Is(err, ErrClassRefused) {
			t.Fatalf("%s: got %v", p, err)
		}
	}
	if _, err := rt.RoundTrip(get(t, context.Background(), "PUT", itemURL)); !errors.Is(err, ErrClassRefused) {
		t.Fatalf("method not in model: got %v", err)
	}
	if calls != 0 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestGuardMostRestrictiveClassWins(t *testing.T) {
	g, _ := newTestGuard(t, nil, GuardOptions{})
	var calls int32
	rt := g.Transport(okTransport(&calls))
	// /api/x/special matches a read template and a money template
	if _, err := rt.RoundTrip(get(t, context.Background(), "GET", uatOrigin+"/api/x/special")); !errors.Is(err, ErrClassRefused) {
		t.Fatalf("got %v", err)
	}
	r, err := rt.RoundTrip(get(t, context.Background(), "GET", uatOrigin+"/api/x/other"))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
}

func TestGuardMoneyAllowedOnlyWhenEngagementPermits(t *testing.T) {
	g, _ := newTestGuard(t, func(e *Engagement) {
		e.SimulatedRail = true
		e.SimulatorBeneficiaries = []string{"SIM"}
		e.Operations = []string{"POST /api/pay", "GET /api/pay"}
	}, GuardOptions{})
	var calls int32
	rt := g.Transport(okTransport(&calls))
	r, err := rt.RoundTrip(get(t, context.Background(), "POST", uatOrigin+"/api/pay"))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	// the allowlist now also applies to reads
	if _, err := rt.RoundTrip(get(t, context.Background(), "GET", itemURL)); !errors.Is(err, ErrClassRefused) {
		t.Fatalf("got %v", err)
	}
}

func TestLimiterCapsConcurrency(t *testing.T) {
	g, _ := newTestGuard(t, func(e *Engagement) { e.MaxConcurrent = 2 }, GuardOptions{Sleep: func(context.Context, time.Duration) error { return nil }})
	var cur, max int32
	release := make(chan struct{})
	rt := g.Transport(rtFunc(func(*http.Request) (*http.Response, error) {
		n := atomic.AddInt32(&cur, 1)
		for {
			m := atomic.LoadInt32(&max)
			if n <= m || atomic.CompareAndSwapInt32(&max, m, n) {
				break
			}
		}
		<-release
		atomic.AddInt32(&cur, -1)
		return resp(200), nil
	}))
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := rt.RoundTrip(get(t, context.Background(), "GET", itemURL))
			if err == nil {
				r.Body.Close()
			}
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&cur) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // give extra goroutines the chance to (wrongly) get through
	if got := atomic.LoadInt32(&cur); got != 2 {
		t.Fatalf("in flight = %d, want exactly 2", got)
	}
	close(release)
	wg.Wait()
	if atomic.LoadInt32(&max) != 2 {
		t.Fatalf("max in flight = %d", max)
	}
}

func TestLimiterCapsRPS(t *testing.T) {
	g, clk := newTestGuard(t, func(e *Engagement) { e.RPS = 4 }, GuardOptions{})
	var calls int32
	rt := g.Transport(okTransport(&calls))
	for i := 0; i < 4; i++ {
		r, err := rt.RoundTrip(get(t, context.Background(), "GET", itemURL))
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
	}
	want := []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, 750 * time.Millisecond}
	if len(clk.sleeps) != len(want) {
		t.Fatalf("sleeps = %v, want %v", clk.sleeps, want)
	}
	for i := range want {
		if clk.sleeps[i] != want[i] {
			t.Fatalf("sleeps = %v, want %v", clk.sleeps, want)
		}
	}
	// time passing refills the bucket: no wait is needed after a long gap
	clk.Advance(10 * time.Second)
	n := len(clk.sleeps)
	r, _ := rt.RoundTrip(get(t, context.Background(), "GET", itemURL))
	r.Body.Close()
	if len(clk.sleeps) != n {
		t.Fatalf("waited after an idle period: %v", clk.sleeps)
	}
}

func TestBudgetExhaustionEndsRun(t *testing.T) {
	g, _ := newTestGuard(t, func(e *Engagement) { e.MaxRequests = 3 }, GuardOptions{})
	var calls int32
	rt := g.Transport(okTransport(&calls))
	for i := 0; i < 3; i++ {
		r, err := rt.RoundTrip(get(t, context.Background(), "GET", itemURL))
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
	}
	if _, err := rt.RoundTrip(get(t, context.Background(), "GET", itemURL)); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("got %v", err)
	}
	if calls != 3 {
		t.Fatalf("calls=%d", calls)
	}
	if st := g.Stats(); st.Requests != 3 || st.Refused != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func statusTransport(codes ...int) http.RoundTripper {
	var i int32
	return rtFunc(func(*http.Request) (*http.Response, error) {
		n := int(atomic.AddInt32(&i, 1)) - 1
		c := 200
		if n < len(codes) {
			c = codes[n]
		}
		return resp(c), nil
	})
}

func send(t *testing.T, rt http.RoundTripper) error {
	t.Helper()
	r, err := rt.RoundTrip(get(t, context.Background(), "GET", itemURL))
	if err == nil {
		r.Body.Close()
	}
	return err
}

func TestBreakerHaltsOn429(t *testing.T) {
	g, _ := newTestGuard(t, nil, GuardOptions{})
	rt := g.Transport(statusTransport(429, 200))
	if err := send(t, rt); err != nil {
		t.Fatalf("the 429 itself is returned to the caller: %v", err)
	}
	if err := send(t, rt); !errors.Is(err, ErrHalted) {
		t.Fatalf("got %v", err)
	}
	if err := g.Halt(); !errors.Is(err, ErrHalted) {
		t.Fatalf("Halt() = %v", err)
	}
}

func TestBreakerHaltsOnThreeConsecutive5xx(t *testing.T) {
	g, _ := newTestGuard(t, nil, GuardOptions{})
	rt := g.Transport(statusTransport(500, 502, 200, 503, 500, 504, 200))
	for i := 0; i < 5; i++ { // 500 502 200 503 500: never three in a row
		if err := send(t, rt); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if g.Halt() != nil {
		t.Fatal("two 5xx then a 200 must not trip")
	}
	if err := send(t, rt); err != nil { // 504 -> third consecutive
		t.Fatal(err)
	}
	if err := send(t, rt); !errors.Is(err, ErrHalted) {
		t.Fatalf("got %v", err)
	}
}

func TestBreakerHaltsOnLatency(t *testing.T) {
	g, clk := newTestGuard(t, nil, GuardOptions{LatencyLimit: 100 * time.Millisecond})
	var delay atomic.Int64
	rt := g.Transport(rtFunc(func(*http.Request) (*http.Response, error) {
		clk.Advance(time.Duration(delay.Load()))
		return resp(200), nil
	}))
	slow, fast := int64(200*time.Millisecond), int64(10*time.Millisecond)
	for _, d := range []int64{slow, slow, fast, slow, slow} {
		delay.Store(d)
		if err := send(t, rt); err != nil {
			t.Fatal(err)
		}
	}
	if g.Halt() != nil {
		t.Fatal("non-consecutive slow requests tripped the breaker")
	}
	delay.Store(slow)
	if err := send(t, rt); err != nil { // third consecutive slow
		t.Fatal(err)
	}
	if err := send(t, rt); !errors.Is(err, ErrHalted) {
		t.Fatalf("got %v", err)
	}
}

func TestStopRefusesAndCancelsInFlight(t *testing.T) {
	g, _ := newTestGuard(t, nil, GuardOptions{})
	started := make(chan struct{})
	rt := g.Transport(rtFunc(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	}))
	done := make(chan error, 1)
	go func() {
		_, err := rt.RoundTrip(get(t, context.Background(), "GET", itemURL))
		done <- err
	}()
	<-started
	g.Stop()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("in-flight request survived Stop")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight request not cancelled by Stop")
	}
	if err := send(t, rt); !errors.Is(err, ErrStopped) {
		t.Fatalf("got %v", err)
	}
	if !errors.Is(g.Halt(), ErrStopped) {
		t.Fatalf("Halt() = %v", g.Halt())
	}
}

func TestCleanupExemptFromBreakerStopAndBudgetButNotClassOrOrigin(t *testing.T) {
	g, clk := newTestGuard(t, func(e *Engagement) { e.MaxRequests = 1 }, GuardOptions{})
	var calls int32
	rt := g.Transport(okTransport(&calls))
	if err := send(t, rt); err != nil { // spends the whole budget
		t.Fatal(err)
	}
	g.Stop()
	g.trip("test")
	cctx := WithCleanup(context.Background())
	if err := send(t, rt); err == nil {
		t.Fatal("non-cleanup request ran after stop")
	}
	del := func(url string) error {
		r, err := rt.RoundTrip(get(t, cctx, "DELETE", url))
		if err == nil {
			r.Body.Close()
		}
		return err
	}
	if err := del(itemURL); err != nil {
		t.Fatalf("cleanup must be exempt from stop, breaker and budget: %v", err)
	}
	if err := del("https://evil.example:8443/api/items/1"); err == nil {
		t.Fatal("cleanup reached an unlisted origin")
	}
	for _, m := range []string{"POST"} {
		if r, err := rt.RoundTrip(get(t, cctx, m, uatOrigin+"/api/pay")); !errors.Is(err, ErrClassRefused) {
			if err == nil {
				r.Body.Close()
			}
			t.Fatalf("cleanup ran a money operation: %v", err)
		}
	}
	if _, err := rt.RoundTrip(get(t, cctx, "GET", uatOrigin+"/api/mystery")); !errors.Is(err, ErrClassRefused) {
		t.Fatalf("cleanup ran an unknown operation: %v", err)
	}
	clk.Advance(48 * time.Hour)
	if err := del(itemURL); !errors.Is(err, ErrOutsideWindow) {
		t.Fatalf("cleanup outside the window: %v", err)
	}
}

func TestWindowExpiryMidRunRefuses(t *testing.T) {
	g, clk := newTestGuard(t, nil, GuardOptions{})
	var calls int32
	rt := g.Transport(okTransport(&calls))
	if err := send(t, rt); err != nil {
		t.Fatal(err)
	}
	clk.Advance(25 * time.Hour)
	if err := send(t, rt); !errors.Is(err, ErrOutsideWindow) {
		t.Fatalf("got %v", err)
	}
	if !errors.Is(g.Halt(), ErrOutsideWindow) {
		t.Fatalf("Halt() = %v", g.Halt())
	}
}

func TestNewGuardValidatesEngagementAtConstruction(t *testing.T) {
	e := uatEngagement()
	e.Environment = "production"
	if _, err := NewGuard(e, uatScope(), guardModel(), GuardOptions{Now: func() time.Time { return t0 }}); err == nil {
		t.Fatal("production guard constructed")
	}
	e = uatEngagement()
	if _, err := NewGuard(e, nil, guardModel(), GuardOptions{Now: func() time.Time { return t0 }}); err == nil {
		t.Fatal("UAT guard without scope constructed")
	}
	if _, err := NewGuard(e, uatScope(), guardModel(), GuardOptions{Now: func() time.Time { return t0.Add(48 * time.Hour) }}); err == nil {
		t.Fatal("expired guard constructed")
	}
}

func labGuard(t *testing.T, srvURL string) *Guard {
	t.Helper()
	e := uatEngagement()
	e.Environment = "lab"
	e.Hosts = []string{srvURL}
	e.RPS = 1e6
	e.MaxRequests = 1000
	g, err := NewGuard(e, nil, guardModel(), GuardOptions{Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGuardNeverFollowsRedirects(t *testing.T) {
	var hits atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/api/items/1" {
			http.Redirect(w, r, srv.URL+"/api/items/2", http.StatusFound)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	g := labGuard(t, srv.URL)

	// a client that follows redirects by default still never follows one
	c := &http.Client{Transport: g.Transport(http.DefaultTransport)}
	r, err := c.Get(srv.URL + "/api/items/1")
	if err == nil {
		r.Body.Close()
		t.Fatal("redirect followed through Transport")
	}
	if !errors.Is(err, ErrRedirect) {
		t.Fatalf("got %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("redirect target was requested: hits=%d", hits.Load())
	}

	// an *http.Client Doer is rewrapped so the redirect target is never requested
	hits.Store(0)
	d, err := g.WrapDoer(&http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := d.Do(get(t, context.Background(), "GET", srv.URL+"/api/items/1"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || hits.Load() != 1 {
		t.Fatalf("status=%d hits=%d: redirect must be returned, not followed", resp.StatusCode, hits.Load())
	}

}

func TestWrapDoerEnforcesGuard(t *testing.T) {
	g, _ := newTestGuard(t, nil, GuardOptions{})
	var calls int32
	d, err := g.WrapDoer(&http.Client{Transport: okTransport(&calls)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Do(get(t, context.Background(), "GET", "https://evil.example/api/items/1")); err == nil {
		t.Fatal("doer reached an unlisted origin")
	}
	r, err := d.Do(get(t, context.Background(), "GET", itemURL))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestWrapDoerRefusesNonClientDoer(t *testing.T) {
	g, _ := newTestGuard(t, nil, GuardOptions{})
	if _, err := g.WrapDoer(doerFunc(func(*http.Request) (*http.Response, error) { return resp(200), nil })); err == nil {
		t.Fatal("custom Doer accepted")
	}
	var nilClient *http.Client
	if _, err := g.WrapDoer(nilClient); err == nil {
		t.Fatal("nil client accepted")
	}
}

func overlapGuard(t *testing.T) *Guard {
	g, _ := newTestGuard(t, nil, GuardOptions{})
	return g
}

func TestOverrideKeysWrittenDirectlyAreExamined(t *testing.T) {
	g := overlapGuard(t)
	var calls int32
	rt := g.Transport(okTransport(&calls))
	for _, k := range []string{"X-HTTP-Method-Override", "x-http-method-override", "X-Http-Method-OVERRIDE", "X-Method-Override", "x-method-override", "X-HTTP-Method", "x-http-method"} {
		for _, v := range []string{"POST", " post ", "GET, POST"} {
			rq := get(t, context.Background(), "GET", uatOrigin+"/api/pay")
			rq.Header[k] = []string{v}
			if _, err := rt.RoundTrip(rq); !errors.Is(err, ErrClassRefused) {
				t.Fatalf("key %q value %q: got %v", k, v, err)
			}
		}
	}
	for _, q := range []string{"_METHOD=POST", "_Method=post", "_method=POST"} {
		rq := get(t, context.Background(), "GET", uatOrigin+"/api/pay?"+q)
		if _, err := rt.RoundTrip(rq); !errors.Is(err, ErrClassRefused) {
			t.Fatalf("%s: got %v", q, err)
		}
	}
	if calls != 0 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestPathSmugglingFormsAreRefused(t *testing.T) {
	g := overlapGuard(t)
	var calls int32
	rt := g.Transport(okTransport(&calls))
	for _, p := range []string{
		"/api/x/special;a=1", "/api/x/Special", "/api/x/SPECIAL", "/api/x/special%20", "/api/x/%20special",
		"/api/x/special%252e", "/api/x/special%2e", "/api/x/special%5c", "/api/x/spec%3bial", "/api/x/special%00",
		"/api/x/ special",
	} {
		rq, err := http.NewRequest("GET", uatOrigin+p, nil)
		if err != nil {
			continue // not even constructible
		}
		if _, err := rt.RoundTrip(rq); !errors.Is(err, ErrClassRefused) {
			t.Fatalf("%s: got %v", p, err)
		}
	}
	if calls != 0 {
		t.Fatalf("calls=%d", calls)
	}
	r, err := rt.RoundTrip(get(t, context.Background(), "GET", uatOrigin+"/api/x/abc"))
	if err != nil {
		t.Fatalf("a normal id must still be allowed: %v", err)
	}
	r.Body.Close()
}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestCheckOrigin(t *testing.T) {
	g, _ := newTestGuard(t, nil, GuardOptions{})
	if err := g.CheckOrigin(uatOrigin + "/some/prefix"); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"https://evil.example", "https://u@uat.bank.example:8443", "", "uat.bank.example"} {
		if err := g.CheckOrigin(u); err == nil {
			t.Fatalf("%q accepted", u)
		}
	}
}

// Backstop independent of how classes were chosen: a state-changing method is never "read".
func TestAllowRefusesNonGetClassedRead(t *testing.T) {
	e := uatEngagement()
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		op := model.Operation{ID: "o", Method: m, Path: "/p", Class: model.ClassRead}
		if err := Allow(ClassRead, op, e); !errors.Is(err, ErrClassRefused) {
			t.Fatalf("%s classed read was allowed: %v", m, err)
		}
	}
	for _, m := range []string{"GET", "HEAD", "OPTIONS"} {
		op := model.Operation{ID: "o", Method: m, Path: "/p", Class: model.ClassRead}
		if err := Allow(ClassRead, op, e); err != nil {
			t.Fatalf("%s read refused: %v", m, err)
		}
	}
}

func TestGuardRefusesPostClassedRead(t *testing.T) {
	m := model.Model{Operations: []model.Operation{{ID: "settle", Method: "POST", Path: "/api/settle", Class: model.ClassRead}}}
	g, err := NewGuard(func() Engagement { e := uatEngagement(); e.RPS = 1e6; e.MaxRequests = 10; return e }(), uatScope(), m,
		GuardOptions{Now: func() time.Time { return t0 }, Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest("POST", uatOrigin+"/api/settle", nil)
	if err := g.preflight(r); !errors.Is(err, ErrClassRefused) {
		t.Fatalf("POST classed read: %v", err)
	}
}

// The Guard classifies the FINAL request by matching its method and concrete path to the model, and
// applies the engagement's list by signature. The operation id (analyst-controlled) plays no part: an
// entry that is only an id lists nothing, and an operation that takes a listed id gains nothing.
func TestGuardClassifiesByFinalMethodAndPathNotByOperationID(t *testing.T) {
	var calls int32
	bad := uatEngagement()
	bad.RPS, bad.MaxRequests = 1e6, 10
	bad.SimulatedRail, bad.SimulatorBeneficiaries = true, []string{"SIM"}
	bad.Operations = []string{"pay"} // an id, not a signature: the engagement is invalid, so no guard is built
	if _, err := NewGuard(bad, uatScope(), guardModel(), GuardOptions{}); !errors.Is(err, ErrInvalidEngagement) {
		t.Fatalf("an id-only operations list was accepted: %v", err)
	}
	// A model whose analyst-chosen id equals the listed text, but whose route differs, is still refused.
	m := model.Model{Operations: []model.Operation{{ID: "POST /api/pay", Method: "POST", Path: "/api/settle", Class: model.ClassMoney}}}
	e := uatEngagement()
	e.RPS, e.MaxRequests = 1e6, 10
	e.SimulatedRail, e.SimulatorBeneficiaries = true, []string{"SIM"}
	e.Operations = []string{"POST /api/pay"}
	g2, err := NewGuard(e, uatScope(), m, GuardOptions{Now: func() time.Time { return t0 }, Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g2.Transport(okTransport(&calls)).RoundTrip(get(t, context.Background(), "POST", uatOrigin+"/api/settle")); !errors.Is(err, ErrClassRefused) {
		t.Fatalf("operation with a listed id string but another route was allowed: %v", err)
	}
}

// ---- the engagement's own route list is enforced by the Guard, whatever the run document contains ----

func engGuard(t *testing.T, m model.Model, mut func(*Engagement)) *Guard {
	t.Helper()
	e := uatEngagement()
	e.RPS, e.MaxRequests = 1e6, 100
	if mut != nil {
		mut(&e)
	}
	g, err := NewGuard(e, uatScope(), m, GuardOptions{Now: func() time.Time { return t0 }, Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func paramOnlyModel(class model.OpClass) model.Model {
	return model.Model{Operations: []model.Operation{{ID: "xAny", Method: "GET", Path: "/api/x/{a}", Class: class}}}
}

// The probe: the document has only GET /api/x/{a} (read). The engagement classes GET /api/x/special as
// money. A request to the literal route must be judged as money, not as the looser param operation.
func TestGuardEnforcesEngagementRouteMissingFromTheDocument(t *testing.T) {
	var calls int32
	g := engGuard(t, paramOnlyModel(model.ClassRead), func(e *Engagement) {
		e.Classes = map[string]string{"GET /api/x/special": "money"}
	})
	rt := g.Transport(okTransport(&calls))
	if _, err := rt.RoundTrip(get(t, context.Background(), "GET", uatOrigin+"/api/x/special")); !errors.Is(err, ErrClassRefused) {
		t.Fatalf("money route reached through the param operation: %v", err)
	}
	if calls != 0 {
		t.Fatalf("%d requests reached the target", calls)
	}
	// other values of the parameter are still plain reads
	if r, err := rt.RoundTrip(get(t, context.Background(), "GET", uatOrigin+"/api/x/other")); err != nil {
		t.Fatalf("ordinary read refused: %v", err)
	} else {
		r.Body.Close()
	}
	// money needs the rail, beneficiaries AND the explicit listing; all present: allowed
	g2 := engGuard(t, paramOnlyModel(model.ClassRead), func(e *Engagement) {
		e.Classes = map[string]string{"GET /api/x/special": "money"}
		e.SimulatedRail, e.SimulatorBeneficiaries = true, []string{"SIM"}
		e.Operations = []string{"GET /api/x/special", "GET /api/x/{}"}
	})
	if r, err := g2.Transport(okTransport(&calls)).RoundTrip(get(t, context.Background(), "GET", uatOrigin+"/api/x/special")); err != nil {
		t.Fatalf("declared money route refused: %v", err)
	} else {
		r.Body.Close()
	}
	// rail declared but the route not listed: refused
	g3 := engGuard(t, paramOnlyModel(model.ClassRead), func(e *Engagement) {
		e.Classes = map[string]string{"GET /api/x/special": "money"}
		e.SimulatedRail, e.SimulatorBeneficiaries = true, []string{"SIM"}
		e.Operations = []string{"GET /api/x/{}"}
	})
	if _, err := g3.Transport(okTransport(&calls)).RoundTrip(get(t, context.Background(), "GET", uatOrigin+"/api/x/special")); !errors.Is(err, ErrClassRefused) {
		t.Fatalf("unlisted money route allowed: %v", err)
	}
}

// The reverse: the engagement classes the literal route read while the param operation is money. The
// most restrictive candidate decides, in either direction.
func TestGuardMostRestrictiveCandidateWinsInEitherDirection(t *testing.T) {
	var calls int32
	g := engGuard(t, paramOnlyModel(model.ClassMoney), func(e *Engagement) {
		e.Classes = map[string]string{"GET /api/x/special": "read"}
	})
	if _, err := g.Transport(okTransport(&calls)).RoundTrip(get(t, context.Background(), "GET", uatOrigin+"/api/x/special")); !errors.Is(err, ErrClassRefused) {
		t.Fatalf("looser literal class beat the money param operation: %v", err)
	}
	if calls != 0 {
		t.Fatal("request reached the target")
	}
}

func TestGuardEngagementUnknownClassRefuses(t *testing.T) {
	var calls int32
	g := engGuard(t, paramOnlyModel(model.ClassRead), func(e *Engagement) {
		e.Classes = map[string]string{"GET /api/x/special": "unknown"}
	})
	if _, err := g.Transport(okTransport(&calls)).RoundTrip(get(t, context.Background(), "GET", uatOrigin+"/api/x/special")); !errors.Is(err, ErrClassRefused) || calls != 0 {
		t.Fatalf("unknown engagement class allowed: %v (%d calls)", err, calls)
	}
}

// A path that matches an engagement route only when case is ignored may reach it on a case-insensitive
// server, so it is refused, like the model's own case rule.
func TestGuardEngagementRouteCaseFoldVariantRefused(t *testing.T) {
	var calls int32
	g := engGuard(t, paramOnlyModel(model.ClassRead), func(e *Engagement) {
		e.Classes = map[string]string{"GET /api/x/special": "money"}
	})
	for _, p := range []string{"/api/x/SPECIAL", "/api/x/Special"} {
		if _, err := g.Transport(okTransport(&calls)).RoundTrip(get(t, context.Background(), "GET", uatOrigin+p)); !errors.Is(err, ErrClassRefused) {
			t.Fatalf("%s: %v", p, err)
		}
	}
	if calls != 0 {
		t.Fatal("request reached the target")
	}
}

// The decision does not depend on map order: the same engagement built many times refuses with the same error.
func TestGuardEngagementRouteOrderIsDeterministic(t *testing.T) {
	var first string
	for i := 0; i < 30; i++ {
		var calls int32
		g := engGuard(t, paramOnlyModel(model.ClassRead), func(e *Engagement) {
			e.Classes = map[string]string{"GET /api/x/{}": "read", "GET /api/x/special": "money", "GET /api/{}/special": "notifying", "GET /api/x/spe{}": "read"}
			delete(e.Classes, "GET /api/x/spe{}")
		})
		_, err := g.Transport(okTransport(&calls)).RoundTrip(get(t, context.Background(), "GET", uatOrigin+"/api/x/special"))
		if !errors.Is(err, ErrClassRefused) || calls != 0 {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if i == 0 {
			first = err.Error()
		} else if err.Error() != first {
			t.Fatalf("non-deterministic refusal: %q vs %q", err.Error(), first)
		}
	}
}
