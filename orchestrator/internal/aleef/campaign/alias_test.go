package campaign

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/aleef/model"
)

type fakeNext struct {
	calls int
	got   *http.Request
	body  string
	resp  func() *http.Response
}

func (f *fakeNext) RoundTrip(r *http.Request) (*http.Response, error) {
	f.calls++
	f.got = r
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		f.body = string(b)
	}
	if f.resp != nil {
		return f.resp(), nil
	}
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
}

func jsonResp(body string) func() *http.Response {
	return func() *http.Response {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
	}
}

func aliasModel(t *testing.T) model.Model {
	m, err := model.Import([]byte(toySpec))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func newTestAlias(t *testing.T, gen, fresh []string) (http.RoundTripper, *fakeNext) {
	t.Helper()
	nx := &fakeNext{}
	rt, err := newAlias(nx, gen, fresh, aliasModel(t))
	if err != nil {
		t.Fatal(err)
	}
	return rt, nx
}

func req(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAliasTranslatesEveryWholeTokenForm(t *testing.T) {
	rt, nx := newTestAlias(t, []string{"item-1", "item-2"}, []string{"item-7", "item-8"})
	r := req(t, "POST", "http://h/api/v2/items/item-1/archive?ref=item-2&x=y", `{"a":["item-1",{"b":"item-1","c":"keep"}],"d":"item-2"}`)
	r.Header.Set("X-Ref", "item-2")
	r.Header.Set("Authorization", "Bearer item-1-token")
	r.Header.Set("Accept-Encoding", "gzip")
	if _, err := rt.RoundTrip(r); err != nil {
		t.Fatal(err)
	}
	if nx.got.URL.Path != "/api/v2/items/item-7/archive" || nx.got.URL.Query().Get("ref") != "item-8" || nx.got.Header.Get("X-Ref") != "item-8" {
		t.Fatalf("not translated: %s %s %v", nx.got.URL.Path, nx.got.URL.RawQuery, nx.got.Header)
	}
	if nx.body != `{"a":["item-7",{"b":"item-7","c":"keep"}],"d":"item-8"}` {
		t.Fatalf("body %s", nx.body)
	}
	if nx.got.Header.Get("Authorization") != "Bearer item-1-token" {
		t.Fatal("credential header was touched")
	}
	if nx.got.Header.Get("Accept-Encoding") != "identity" {
		t.Fatalf("Accept-Encoding %q", nx.got.Header.Get("Accept-Encoding"))
	}
	if r.Header.Get("Accept-Encoding") != "gzip" {
		t.Fatal("caller's request was mutated")
	}
}

func TestAliasRefusesUntranslatableIDs(t *testing.T) {
	cases := map[string]func() *http.Request{
		"id embedded in a longer body string": func() *http.Request {
			return req(t, "POST", "http://h/api/v2/items/item-1/archive", `{"note":"see item-1 please"}`)
		},
		"numeric json id": func() *http.Request {
			return req(t, "POST", "http://h/api/v2/items/42/archive", `{"id":42}`)
		},
		"id inside a header value": func() *http.Request {
			r := req(t, "GET", "http://h/api/v2/items/item-1", "")
			r.Header.Set("X-Probe", "prefix-item-1")
			return r
		},
		"id in an encoded query value": func() *http.Request {
			return req(t, "GET", "http://h/api/v2/items/item-1?ref=a%2Citem-1", "")
		},
		"id embedded in a path segment": func() *http.Request {
			return req(t, "GET", "http://h/api/v2/items/item-1x", "")
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			rt, nx := newTestAlias(t, []string{"item-1", "42"}, []string{"item-7", "43"})
			_, err := rt.RoundTrip(mk())
			if !errors.Is(err, ErrUntranslatedID) {
				t.Fatalf("err %v", err)
			}
			if nx.calls != 0 {
				t.Fatal("request was sent")
			}
		})
	}
}

func TestAliasFreshIDContainingGenerationIDIsNotARefusal(t *testing.T) {
	rt, nx := newTestAlias(t, []string{"item-1"}, []string{"item-12"})
	r := req(t, "POST", "http://h/api/v2/items/item-1/archive?ref=item-1", `{"a":"item-1"}`)
	r.Header.Set("X-Ref", "item-1")
	if _, err := rt.RoundTrip(r); err != nil {
		t.Fatal(err)
	}
	if nx.got.URL.Path != "/api/v2/items/item-12/archive" || nx.body != `{"a":"item-12"}` {
		t.Fatalf("%s %s", nx.got.URL.Path, nx.body)
	}
}

func TestAliasEncodedSegmentAndDuplicates(t *testing.T) {
	rt, nx := newTestAlias(t, []string{"item-1"}, []string{"item-7"})
	if _, err := rt.RoundTrip(req(t, "GET", "http://h/api/v2/items/item%2D1?ref=item-1&ref=item-1", "")); err != nil {
		t.Fatal(err)
	}
	if nx.got.URL.Path != "/api/v2/items/item-7" || strings.Count(nx.got.URL.RawQuery, "item-7") != 2 {
		t.Fatalf("%s ? %s", nx.got.URL.Path, nx.got.URL.RawQuery)
	}
}

func TestAliasResponseTranslation(t *testing.T) {
	rt, nx := newTestAlias(t, []string{"item-1", "item-2"}, []string{"item-7", "item-8"})
	nx.resp = jsonResp(`{"items":[{"id":"item-7"},{"id":"item-8","tags":["item-7","x"]}],"n":7}`)
	resp, err := rt.RoundTrip(req(t, "GET", "http://h/api/v2/items", ""))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != `{"items":[{"id":"item-1"},{"id":"item-2","tags":["item-1","x"]}],"n":7}` {
		t.Fatalf("%s", b)
	}
}

func TestAliasEncodedResponseIsAnError(t *testing.T) {
	rt, nx := newTestAlias(t, []string{"item-1"}, []string{"item-7"})
	nx.resp = func() *http.Response {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": {"gzip"}}, Body: io.NopCloser(bytes.NewReader([]byte{0x1f, 0x8b}))}
	}
	resp, err := rt.RoundTrip(req(t, "GET", "http://h/api/v2/items/item-1", ""))
	if !errors.Is(err, ErrEncodedResponse) || resp != nil {
		t.Fatalf("resp %v err %v", resp, err)
	}
}

func TestAliasBodyCapIsAnErrorNotATruncation(t *testing.T) {
	old := maxAliasBody
	maxAliasBody = 32
	defer func() { maxAliasBody = old }()
	rt, nx := newTestAlias(t, []string{"item-1"}, []string{"item-7"})

	big := `{"a":"` + strings.Repeat("x", 100) + `"}`
	if _, err := rt.RoundTrip(req(t, "POST", "http://h/api/v2/items", big)); !errors.Is(err, ErrAliasBodyTooLarge) || nx.calls != 0 {
		t.Fatalf("request: err %v calls %d", err, nx.calls)
	}
	nx.resp = jsonResp(big)
	if resp, err := rt.RoundTrip(req(t, "GET", "http://h/api/v2/items", "")); !errors.Is(err, ErrAliasBodyTooLarge) || resp != nil {
		t.Fatalf("response: %v %v", resp, err)
	}
	// exactly at the cap is fine
	exact := `{"k":"` + strings.Repeat("y", 32-8) + `"}`
	if len(exact) != 32 {
		t.Fatalf("test setup: %d", len(exact))
	}
	nx.resp = jsonResp(exact)
	resp, err := rt.RoundTrip(req(t, "GET", "http://h/api/v2/items", ""))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(resp.Body); string(b) != exact {
		t.Fatalf("body altered: %s", b)
	}
}

func TestNewAliasRefusesUnsafeIDs(t *testing.T) {
	m := aliasModel(t)
	cases := []struct{ name, gen, fresh string }{
		{"literal route segment", "item-1", "archive"},
		{"literal, other case", "item-1", "Items"},
		{"slash", "item-1", "a/b"},
		{"encoded slash", "item-1", "a%2Fb"},
		{"dot segment", "item-1", ".."},
		{"space", "item-1", "a b"},
		{"matrix parameter", "item-1", "a;b"},
		{"empty", "item-1", ""},
		{"literal as generation id", "v2", "item-9"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := newAlias(&fakeNext{}, []string{c.gen}, []string{c.fresh}, m); err == nil {
				t.Fatalf("ids %q/%q accepted", c.gen, c.fresh)
			}
		})
	}
	rt, err := newAlias(&fakeNext{}, []string{"item-1"}, []string{"item-1"}, m)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rt.(aliasRT); ok {
		t.Fatal("identical namespaces must not install a translator")
	}
}

func TestRewriteJSONEdges(t *testing.T) {
	m := map[string]string{"a": "b", "id-1": "id-9"}
	in := `{"a":"a","k":["a",["id-1",{"x":"id-1"}]],"s":"say \"a\"","a2":"aa","n":1}`
	want := `{"b":"b","k":["b",["id-9",{"x":"id-9"}]],"s":"say \"a\"","a2":"aa","n":1}`
	if got := string(rewriteJSON([]byte(in), m)); got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
}
