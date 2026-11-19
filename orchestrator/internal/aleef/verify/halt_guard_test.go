package verify

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/safety"
)

type haltRT func(*http.Request) (*http.Response, error)

func (f haltRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestVerifyHaltWiresToGuard(t *testing.T) {
	now := time.Now()
	e := safety.Engagement{ID: "e", Customer: "toy", Environment: "lab", Hosts: []string{"http://127.0.0.1:1"}, Approver: "a",
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), MaxRequests: 100, MaxConcurrent: 2, RPS: 1e6}
	m := model.Model{Operations: []model.Operation{{ID: "get", Method: "GET", Path: "/x", Class: model.ClassRead}}}
	g, err := safety.NewGuard(e, nil, m, safety.GuardOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rt := g.Transport(haltRT(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 429, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	}))
	req, _ := http.NewRequest("GET", "http://127.0.0.1:1/x", nil)
	resp, err := rt.RoundTrip(req) // the 429 trips the breaker
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	ty := newToy()
	ty.readFlaw = stable
	env, rec := newEnv(t, ty), newRec()
	v := run(t, env, rec, Options{Halt: g.Halt}, ownTest(t))
	if v.State != StateUnconfirmed || !strings.HasPrefix(v.Reason, "halted: ") || env.fresh.Load() != 0 || len(rec.findings) != 0 {
		t.Fatalf("verdict %+v fresh=%d", v, env.fresh.Load())
	}
}
