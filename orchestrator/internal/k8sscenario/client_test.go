package k8sscenario

import (
	"bytes"
	"context"

	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder captures every request the client sends, so tests can prove what was and was not sent.
type recorder struct {
	mu   sync.Mutex
	reqs []recorded
}

type recorded struct {
	Method, Path, ContentType, Auth string
	Body                            string
}

func (r *recorder) add(req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewReader(body)) // leave the body readable for the handler
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, recorded{Method: req.Method, Path: req.URL.Path, ContentType: req.Header.Get("Content-Type"), Auth: req.Header.Get("Authorization"), Body: string(body)})
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reqs)
}

const testToken = "SECRET-TOKEN-VALUE-do-not-leak"

// newAPIServer returns a TLS server. handle decides each response. Requests without the right token get 401.
func newAPIServer(t *testing.T, rec *recorder, handle func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r)
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handle(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestAPIClient(t *testing.T, srv *httptest.Server) *APIClient {
	t.Helper()
	c, err := NewAPIClient(ClientConfig{APIServer: srv.URL, Token: testToken, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAPIClient_RequiresHTTPSAndToken(t *testing.T) {
	if _, err := NewAPIClient(ClientConfig{APIServer: "http://insecure", Token: testToken}); err == nil {
		t.Fatal("plain http must be refused")
	}
	if _, err := NewAPIClient(ClientConfig{APIServer: "https://127.0.0.1:6443", Token: ""}); err == nil {
		t.Fatal("a missing token must be refused")
	}
	if _, err := NewAPIClient(ClientConfig{APIServer: "https://127.0.0.1:6443", Token: testToken, CAPEM: []byte("not pem")}); err == nil {
		t.Fatal("an unparseable CA must be refused")
	}
}

func TestAPIClient_CreatePodSendsUnprivilegedSpecWithRunLabel(t *testing.T) {
	rec := &recorder{}
	srv := newAPIServer(t, rec, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusCreated) })
	c := newTestAPIClient(t, srv)
	err := c.Create(context.Background(), Object{
		Ref:    ObjectRef{Kind: "Pod", Namespace: "bas-sandbox", Name: "bas-sbx-probe"},
		Labels: map[string]string{RunLabel: "run-1"},
		Spec:   map[string]any{"automountServiceAccountToken": false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.reqs) != 1 || rec.reqs[0].Method != http.MethodPost || rec.reqs[0].Path != "/api/v1/namespaces/bas-sandbox/pods" {
		t.Fatalf("requests = %+v, want one POST to the sandbox pods collection", rec.reqs)
	}
	var body struct {
		Metadata struct {
			Name   string            `json:"name"`
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
		Spec map[string]any `json:"spec"`
	}
	if err := json.Unmarshal([]byte(rec.reqs[0].Body), &body); err != nil {
		t.Fatal(err)
	}
	if body.Metadata.Labels[RunLabel] != "run-1" || body.Metadata.Name != "bas-sbx-probe" {
		t.Fatalf("metadata = %+v, want name and run label", body.Metadata)
	}
	if body.Spec["automountServiceAccountToken"] != false {
		t.Fatal("the spec must disable the service account token")
	}
}

func TestAPIClient_SetDataEmptyValueRemovesKeyWithMergePatch(t *testing.T) {
	rec := &recorder{}
	srv := newAPIServer(t, rec, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	c := newTestAPIClient(t, srv)
	if err := c.SetData(context.Background(), ObjectRef{Kind: "ConfigMap", Namespace: "bas-sandbox", Name: "bas-fixture"}, map[string]string{"state": "", "other": "x"}); err != nil {
		t.Fatal(err)
	}
	r := rec.reqs[0]
	if r.Method != http.MethodPatch || r.ContentType != "application/merge-patch+json" || r.Path != "/api/v1/namespaces/bas-sandbox/configmaps/bas-fixture" {
		t.Fatalf("request = %+v, want a merge patch on the ConfigMap", r)
	}
	var body struct {
		Data map[string]any `json:"data"`
	}
	_ = json.Unmarshal([]byte(r.Body), &body)
	if v, ok := body.Data["state"]; !ok || v != nil {
		t.Fatalf("empty value must send null to remove the key; data=%v", body.Data)
	}
	if body.Data["other"] != "x" {
		t.Fatalf("data=%v, want other=x", body.Data)
	}
}

func TestAPIClient_RefusesKindsOutsideTheRegistry_WithoutSendingAnything(t *testing.T) {
	rec := &recorder{}
	srv := newAPIServer(t, rec, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	c := newTestAPIClient(t, srv)
	ctx := context.Background()
	if _, _, err := c.Get(ctx, ObjectRef{Kind: "Secret", Namespace: "bas-sandbox", Name: "db"}); err == nil {
		t.Fatal("reading a Secret must be refused")
	}
	if err := c.Create(ctx, Object{Ref: ObjectRef{Kind: "Secret", Namespace: "bas-sandbox", Name: "x"}}); err == nil {
		t.Fatal("creating a Secret must be refused")
	}
	if err := c.SetData(ctx, ObjectRef{Kind: "Pod", Namespace: "bas-sandbox", Name: "p"}, map[string]string{"state": "x"}); err == nil {
		t.Fatal("patching a Pod's data must be refused")
	}
	if err := c.Delete(ctx, ObjectRef{Kind: "Namespace", Name: "bas-sandbox"}); err == nil {
		t.Fatal("deleting a Namespace must be refused")
	}
	if err := c.Create(ctx, Object{Ref: ObjectRef{Kind: "Pod", Name: "p"}}); err == nil {
		t.Fatal("a write without a namespace must be refused")
	}
	if rec.count() != 0 {
		t.Fatalf("refused operations sent %d requests", rec.count())
	}
}

func TestAPIClient_NotFoundIsAbsenceNotError(t *testing.T) {
	rec := &recorder{}
	srv := newAPIServer(t, rec, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	c := newTestAPIClient(t, srv)
	_, exists, err := c.Get(context.Background(), ObjectRef{Kind: "Pod", Namespace: "bas-sandbox", Name: "gone"})
	if err != nil || exists {
		t.Fatalf("exists=%v err=%v, want absent with no error", exists, err)
	}
	labels, nsExists, err := c.NamespaceLabels(context.Background(), "missing")
	if err != nil || nsExists || labels != nil {
		t.Fatalf("namespace exists=%v labels=%v err=%v, want absent", nsExists, labels, err)
	}
}

func TestAPIClient_UnauthorizedIsAnError(t *testing.T) {
	rec := &recorder{}
	srv := newAPIServer(t, rec, func(w http.ResponseWriter, r *http.Request) {})
	c, _ := NewAPIClient(ClientConfig{APIServer: srv.URL, Token: "wrong-token", HTTPClient: srv.Client()})
	_, _, err := c.Get(context.Background(), ObjectRef{Kind: "Pod", Namespace: "bas-sandbox", Name: "p"})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestAPIClient_ErrorsNeverContainTheToken(t *testing.T) {
	rec := &recorder{}
	srv := newAPIServer(t, rec, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("echo " + r.Header.Get("Authorization")))
	})
	c := newTestAPIClient(t, srv)
	err := c.Create(context.Background(), Object{Ref: ObjectRef{Kind: "Pod", Namespace: "bas-sandbox", Name: "p"}})
	if err == nil {
		t.Fatal("a 500 must be an error")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatalf("error leaks the token: %v", err)
	}
}

func TestAPIClient_CurrentIdentityParsesSelfSubjectReview(t *testing.T) {
	rec := &recorder{}
	srv := newAPIServer(t, rec, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":{"userInfo":{"username":"` + ScenarioIdentity + `"}}}`))
	})
	c := newTestAPIClient(t, srv)
	id, err := c.CurrentIdentity(context.Background())
	if err != nil || id != ScenarioIdentity {
		t.Fatalf("identity = %q err=%v", id, err)
	}
	if rec.reqs[0].Method != http.MethodPost || rec.reqs[0].Path != "/apis/authentication.k8s.io/v1/selfsubjectreviews" {
		t.Fatalf("request = %+v, want a SelfSubjectReview POST", rec.reqs[0])
	}
}

func TestAPIClient_NamespaceLabelsAreRead(t *testing.T) {
	rec := &recorder{}
	srv := newAPIServer(t, rec, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"metadata":{"name":"bas-sandbox","labels":{"` + SandboxLabel + `":"true"}}}`))
	})
	c := newTestAPIClient(t, srv)
	labels, exists, err := c.NamespaceLabels(context.Background(), "bas-sandbox")
	if err != nil || !exists || labels[SandboxLabel] != "true" {
		t.Fatalf("labels=%v exists=%v err=%v", labels, exists, err)
	}
}

// fakeAPI is a minimal in-memory pod store behind the real HTTP client, to run the engine end to end.
type fakeAPI struct {
	mu   sync.Mutex
	pods map[string]map[string]any
}

func (f *fakeAPI) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	const pre = "/api/v1/namespaces/bas-sandbox/pods"
	switch {
	case r.URL.Path == "/apis/authentication.k8s.io/v1/selfsubjectreviews":
		_, _ = w.Write([]byte(`{"status":{"userInfo":{"username":"` + ScenarioIdentity + `"}}}`))
	case r.URL.Path == "/api/v1/namespaces/bas-sandbox":
		_, _ = w.Write([]byte(`{"metadata":{"name":"bas-sandbox","labels":{"` + SandboxLabel + `":"true"}}}`))
	case r.Method == http.MethodPost && r.URL.Path == pre:
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		name := body["metadata"].(map[string]any)["name"].(string)
		f.pods[name] = body
		w.WriteHeader(http.StatusCreated)
	case strings.HasPrefix(r.URL.Path, pre+"/"):
		name := strings.TrimPrefix(r.URL.Path, pre+"/")
		pod, ok := f.pods[name]
		switch {
		case !ok:
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(pod)
		case r.Method == http.MethodDelete:
			delete(f.pods, name)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestEngineWithAPIClient_PodRunCleansUpOverHTTP(t *testing.T) {
	api := &fakeAPI{pods: map[string]map[string]any{}}
	rec := &recorder{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r)
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		api.handle(w, r)
	}))
	t.Cleanup(srv.Close)
	client, err := NewAPIClient(ClientConfig{APIServer: srv.URL, Token: testToken, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}

	store := newMemApprovals()
	req := RunRequest{RunID: "run-http", Requester: "operator-1", Cluster: ClusterRef{Name: "kind-bas-lab", Server: srv.URL},
		Namespace: "bas-sandbox", ActionID: "pod-create-unprivileged", Params: map[string]string{"name": "bas-sbx-http"}, Live: true}
	_ = store.Put(Approval{ID: "appr-http", ApproverID: "operator-2", RequesterID: "operator-1", RunID: "run-http", Cluster: "kind-bas-lab",
		Namespace: "bas-sandbox", ActionID: req.ActionID, ParamsHash: HashParams(req.Params), ExpiresAt: time.Now().Add(time.Hour)})
	req.ApprovalID = "appr-http"

	cfg := Config{
		AllowedClusters:   map[string]string{"kind-bas-lab": srv.URL},
		AllowedNamespaces: []string{"bas-sandbox"},
		Client:            client,
		Audit:             &recordAudit{},
		Alert:             &recordAlert{},
		Approvals:         store,
		ApproverPermitted: func(id string) bool { return id == "operator-2" },
	}
	res := NewEngine(cfg).Run(context.Background(), req)
	if res.State != StateCleaned || !res.Verified {
		t.Fatalf("state=%s verified=%v err=%q, want cleaned and verified", res.State, res.Verified, res.Error)
	}
	if _, left := api.pods["bas-sbx-http"]; left {
		t.Fatal("the labelled pod must be gone after the run")
	}
	for _, r := range rec.reqs {
		if r.Method == http.MethodPatch || (r.Method == http.MethodPost && strings.Contains(r.Path, "/configmaps")) {
			t.Fatalf("pod action sent a ConfigMap write: %+v", r)
		}
	}
}
