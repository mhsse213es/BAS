package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/k8sscenario"
)

var errFakeAudit = errors.New("audit write failed")

// fakeAuthStore applies the same rules as the database store: a record needs an active tenant, a change and its audit
// event land together or not at all, and a revoke applies once.
type fakeAuthStore struct {
	mu        sync.Mutex
	records   []k8sscenario.CustomerAuthorization
	events    []k8sscenario.Event
	tenants   map[string]bool
	failAudit bool
}

func (f *fakeAuthStore) InsertWithAudit(_ context.Context, a k8sscenario.CustomerAuthorization, ev k8sscenario.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.tenants[a.CustomerRef] {
		return db.ErrCustomerNotFound
	}
	if f.failAudit {
		return errFakeAudit
	}
	f.records = append(f.records, a)
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeAuthStore) Get(_ context.Context, id string) (k8sscenario.CustomerAuthorization, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.records {
		if a.ID == id {
			return a, true, nil
		}
	}
	return k8sscenario.CustomerAuthorization{}, false, nil
}

func (f *fakeAuthStore) List(_ context.Context, clusterID string) ([]k8sscenario.CustomerAuthorization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []k8sscenario.CustomerAuthorization
	for _, a := range f.records {
		if clusterID == "" || a.ClusterID == clusterID {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f *fakeAuthStore) RevokeWithAudit(_ context.Context, id, by string, at time.Time, ev k8sscenario.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, a := range f.records {
		if a.ID != id {
			continue
		}
		if a.RevokedAt != nil {
			return db.ErrAuthorizationRevoked
		}
		if f.failAudit {
			return errFakeAudit
		}
		t := at
		f.records[i].RevokedAt = &t
		f.records[i].RevokedBy = by
		f.events = append(f.events, ev)
		return nil
	}
	return db.ErrAuthorizationNotFound
}

func (f *fakeAuthStore) eventsOf(typ string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, e := range f.events {
		if e.Type == typ {
			n++
		}
	}
	return n
}

var authTestNow = time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)

func authHandler(t *testing.T) (*Handler, *fakeAuthStore, *recordingAudit) {
	t.Helper()
	store := &fakeAuthStore{tenants: map[string]bool{"tenant-acme": true}}
	audit := &recordingAudit{}
	reg := &fakeClusterRegistry{clusters: []k8sscenario.ClusterRecord{
		{ID: "k8sc-lab", DisplayName: "kind-bas-lab", ServerURL: "https://127.0.0.1:61567", Class: k8sscenario.ClassLab},
		{ID: "k8sc-stage", DisplayName: "stage", ServerURL: "https://stage.example:6443", Class: k8sscenario.ClassNonProduction},
		{ID: "k8sc-prod", DisplayName: "prod-east", ServerURL: "https://prod.example:6443", Class: k8sscenario.ClassProduction},
	}}
	svc := &K8sScenarioService{Registry: reg, Authorizations: store, Audit: audit,
		ControlledSwitch: &fakeSwitch{on: true},
		Now:              func() time.Time { return authTestNow }}
	return &Handler{k8sScenario: svc}, store, audit
}

func asAdmin(r *http.Request, id string) *http.Request {
	claims := &auth.Claims{UserID: id, Role: auth.RoleAdmin}
	return r.WithContext(auth.ContextWithClaims(r.Context(), claims))
}

func authURLParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func postAuth(t *testing.T, h *Handler, body string) (int, map[string]any) {
	t.Helper()
	req := asAdmin(httptest.NewRequest(http.MethodPost, "/api/k8s-scenarios/authorizations", strings.NewReader(body)), "admin-1")
	rec := httptest.NewRecorder()
	h.CreateK8sAuthorization(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

const validAuthBody = `{"clusterId":"k8sc-stage","customerRef":"tenant-acme","scenarios":["configmap-patch-labelled"],` +
	`"namespaces":["bas-sandbox"],"expiresAt":"2026-12-04T09:00:00Z"}`

func TestCreateK8sAuthorization_StoresWithItsCreationEvent(t *testing.T) {
	h, store, _ := authHandler(t)
	code, out := postAuth(t, h, validAuthBody)
	if code != http.StatusCreated {
		t.Fatalf("a valid request must be created: %d %v", code, out)
	}
	if out["state"] != "active" || out["authorizedBy"] != "admin-1" {
		t.Errorf("view wrong: %v", out)
	}
	if len(store.records) != 1 || store.eventsOf("k8s.authorization.created") != 1 {
		t.Errorf("the record and its creation event must be stored together: %d records, %+v", len(store.records), store.events)
	}
}

func TestCreateK8sAuthorization_AuditFailureLeavesNoAuthorization(t *testing.T) {
	h, store, _ := authHandler(t)
	store.failAudit = true
	code, _ := postAuth(t, h, validAuthBody)
	if code != http.StatusInternalServerError {
		t.Errorf("a failed audit write must fail the creation: %d", code)
	}
	if len(store.records) != 0 {
		t.Errorf("no active authorization may exist without its creation event: %d", len(store.records))
	}
}

func TestCreateK8sAuthorization_UnknownTenantIsRefused(t *testing.T) {
	h, store, _ := authHandler(t)
	code, _ := postAuth(t, h, strings.Replace(validAuthBody, "tenant-acme", "tenant-nobody", 1))
	if code != http.StatusBadRequest || len(store.records) != 0 {
		t.Errorf("a customerRef that is not an active tenant must be refused and store nothing: %d", code)
	}
}

func TestCreateK8sAuthorization_RefusesProductionAndBadScope(t *testing.T) {
	h, store, _ := authHandler(t)
	cases := map[string]struct {
		body string
		code int
	}{
		"production cluster": {strings.Replace(validAuthBody, "k8sc-stage", "k8sc-prod", 1), http.StatusForbidden},
		"unknown cluster":    {strings.Replace(validAuthBody, "k8sc-stage", "k8sc-missing", 1), http.StatusNotFound},
		"wildcard namespace": {strings.Replace(validAuthBody, `"bas-sandbox"`, `"*"`, 1), http.StatusBadRequest},
		"empty scenarios":    {strings.Replace(validAuthBody, `["configmap-patch-labelled"]`, `[]`, 1), http.StatusBadRequest},
		"unknown field":      {strings.Replace(validAuthBody, `"customerRef"`, `"customer"`, 1), http.StatusBadRequest},
	}
	for name, c := range cases {
		if code, out := postAuth(t, h, c.body); code != c.code {
			t.Errorf("%s: want %d, got %d %v", name, c.code, code, out)
		}
	}
	if len(store.records) != 0 {
		t.Errorf("no refused request may store a record: %d", len(store.records))
	}
}

func TestCreateK8sAuthorization_RequiresAnAdministratorIdentity(t *testing.T) {
	h, store, _ := authHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/k8s-scenarios/authorizations", strings.NewReader(validAuthBody))
	rec := httptest.NewRecorder()
	h.CreateK8sAuthorization(rec, req)
	if rec.Code != http.StatusUnauthorized || len(store.records) != 0 {
		t.Errorf("no identity must be refused and store nothing: %d", rec.Code)
	}
}

func TestRevokeK8sAuthorization_RevokesOnceWithItsEvent(t *testing.T) {
	h, store, _ := authHandler(t)
	postAuth(t, h, validAuthBody)
	id := store.records[0].ID

	revoke := func() *httptest.ResponseRecorder {
		req := authURLParam(asAdmin(httptest.NewRequest(http.MethodPost, "/x", nil), "admin-2"), "id", id)
		rec := httptest.NewRecorder()
		h.RevokeK8sAuthorization(rec, req)
		return rec
	}
	if rec := revoke(); rec.Code != http.StatusOK {
		t.Fatalf("first revoke must succeed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := revoke(); rec.Code != http.StatusConflict {
		t.Errorf("a second revoke must be a conflict: %d", rec.Code)
	}
	if store.records[0].RevokedBy != "admin-2" {
		t.Errorf("the revoking administrator must be recorded: %q", store.records[0].RevokedBy)
	}
	if n := store.eventsOf("k8s.authorization.revoked"); n != 1 {
		t.Errorf("exactly one revoke event must be written, got %d", n)
	}
}

func TestRevokeK8sAuthorization_AuditFailureLeavesRecordActive(t *testing.T) {
	h, store, _ := authHandler(t)
	postAuth(t, h, validAuthBody)
	id := store.records[0].ID
	store.failAudit = true
	req := authURLParam(asAdmin(httptest.NewRequest(http.MethodPost, "/x", nil), "admin-2"), "id", id)
	rec := httptest.NewRecorder()
	h.RevokeK8sAuthorization(rec, req)
	if rec.Code != http.StatusInternalServerError || store.records[0].RevokedAt != nil {
		t.Errorf("a revoke whose audit cannot be written must fail and leave the record active: %d", rec.Code)
	}
}

func TestGetAndListK8sAuthorizations_ReportStateAndFilter(t *testing.T) {
	h, store, _ := authHandler(t)
	postAuth(t, h, validAuthBody)
	id := store.records[0].ID

	get := authURLParam(asAdmin(httptest.NewRequest(http.MethodGet, "/x", nil), "admin-1"), "id", id)
	rec := httptest.NewRecorder()
	h.GetK8sAuthorization(rec, get)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"state":"active"`) {
		t.Errorf("inspect must show the active record: %d %s", rec.Code, rec.Body.String())
	}

	later := &Handler{k8sScenario: &K8sScenarioService{Authorizations: store, Registry: h.k8sScenario.Registry,
		Now: func() time.Time { return authTestNow.AddDate(0, 0, 60) }}}
	rec = httptest.NewRecorder()
	later.ListK8sAuthorizations(rec, asAdmin(httptest.NewRequest(http.MethodGet, "/x?clusterId=k8sc-stage", nil), "admin-1"))
	if !strings.Contains(rec.Body.String(), `"state":"expired"`) {
		t.Errorf("a record past its expiry must list as expired: %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ListK8sAuthorizations(rec, asAdmin(httptest.NewRequest(http.MethodGet, "/x?clusterId=k8sc-lab", nil), "admin-1"))
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("a filter for another cluster must return nothing: %s", rec.Body.String())
	}
}

func TestEnforceCustomerAuthorization_OnlyControlledIsGated(t *testing.T) {
	h, _, _ := authHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	if enforceCustomerAuthorization(rec, req, h.k8sScenario, k8sscenario.ClusterRecord{ID: "k8sc-stage"}, "lab", "configmap-patch-labelled", "bas-sandbox") {
		t.Error("a non-Controlled profile must not be gated by customer authorization")
	}
}

func TestEnforceCustomerAuthorization_DeniesWithoutAMatchingRecord(t *testing.T) {
	h, store, audit := authHandler(t)
	stage := k8sscenario.ClusterRecord{ID: "k8sc-stage", DisplayName: "stage", Class: k8sscenario.ClassNonProduction}

	rec := httptest.NewRecorder()
	if !enforceCustomerAuthorization(rec, httptest.NewRequest(http.MethodPost, "/x", nil), h.k8sScenario, stage,
		"controlled", "configmap-patch-labelled", "bas-sandbox") || rec.Code != http.StatusForbidden {
		t.Fatalf("no authorization must deny Controlled work with 403: %d", rec.Code)
	}
	if len(audit.events) != 1 || audit.events[0].Type != "k8s.authorization.denied" {
		t.Errorf("the denial must be audited: %+v", audit.events)
	}

	postAuth(t, h, validAuthBody)
	rec = httptest.NewRecorder()
	if !enforceCustomerAuthorization(rec, httptest.NewRequest(http.MethodPost, "/x", nil), h.k8sScenario, stage,
		"controlled", "configmap-patch-labelled", "kube-system") {
		t.Error("a mismatched namespace must be denied")
	}

	revokedAt := authTestNow
	store.records[0].RevokedAt = &revokedAt
	rec = httptest.NewRecorder()
	if !enforceCustomerAuthorization(rec, httptest.NewRequest(http.MethodPost, "/x", nil), h.k8sScenario, stage,
		"controlled", "configmap-patch-labelled", "bas-sandbox") {
		t.Error("a revoked record must deny")
	}
}

func TestEnforceCustomerAuthorization_AllowsTheExactMatch(t *testing.T) {
	h, _, _ := authHandler(t)
	postAuth(t, h, validAuthBody)
	stage := k8sscenario.ClusterRecord{ID: "k8sc-stage", DisplayName: "stage", Class: k8sscenario.ClassNonProduction}
	rec := httptest.NewRecorder()
	if enforceCustomerAuthorization(rec, httptest.NewRequest(http.MethodPost, "/x", nil), h.k8sScenario, stage,
		"controlled", "configmap-patch-labelled", "bas-sandbox") {
		t.Errorf("the exact active match must be allowed: %d %s", rec.Code, rec.Body.String())
	}
}

// fakeSwitch is the Controlled kill switch for tests. Set records the change.
type fakeSwitch struct {
	on  bool
	err error
}

func (f *fakeSwitch) Enabled(context.Context) (bool, error) { return f.on, f.err }
func (f *fakeSwitch) Set(_ context.Context, enabled bool, _ string, _ time.Time, _ k8sscenario.Event) error {
	f.on = enabled
	return nil
}

// With the switch off, an otherwise exact authorization is denied, and the denial says why.
func TestEnforceCustomerAuthorization_SwitchOffDenies(t *testing.T) {
	h, _, _ := authHandler(t)
	postAuth(t, h, validAuthBody)
	h.k8sScenario.ControlledSwitch = &fakeSwitch{on: false}
	stage := k8sscenario.ClusterRecord{ID: "k8sc-stage", DisplayName: "stage", Class: k8sscenario.ClassNonProduction}
	rec := httptest.NewRecorder()
	if !enforceCustomerAuthorization(rec, httptest.NewRequest(http.MethodPost, "/x", nil), h.k8sScenario, stage,
		"controlled", "configmap-patch-labelled", "bas-sandbox") {
		t.Fatal("with the switch off, Controlled work must be denied")
	}
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "disabled") {
		t.Fatalf("denial = %d %s, want 403 naming the disabled switch", rec.Code, rec.Body.String())
	}
}

// With no switch configured, Controlled work is denied (fail closed).
func TestEnforceCustomerAuthorization_NoSwitchDeniesFailClosed(t *testing.T) {
	h, _, _ := authHandler(t)
	postAuth(t, h, validAuthBody)
	h.k8sScenario.ControlledSwitch = nil
	stage := k8sscenario.ClusterRecord{ID: "k8sc-stage", DisplayName: "stage", Class: k8sscenario.ClassNonProduction}
	rec := httptest.NewRecorder()
	if !enforceCustomerAuthorization(rec, httptest.NewRequest(http.MethodPost, "/x", nil), h.k8sScenario, stage,
		"controlled", "configmap-patch-labelled", "bas-sandbox") {
		t.Fatal("with no switch configured, Controlled work must be denied")
	}
}

func TestEnforceCustomerAuthorization_NoStoreDeniesFailClosed(t *testing.T) {
	svc := &K8sScenarioService{}
	rec := httptest.NewRecorder()
	stage := k8sscenario.ClusterRecord{ID: "k8sc-stage"}
	if !enforceCustomerAuthorization(rec, httptest.NewRequest(http.MethodPost, "/x", nil), svc, stage,
		"controlled", "configmap-patch-labelled", "bas-sandbox") || rec.Code != http.StatusForbidden {
		t.Errorf("with no store, Controlled work must be denied: %d", rec.Code)
	}
}
