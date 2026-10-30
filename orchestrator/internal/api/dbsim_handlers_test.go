package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbadmin"
)

// These tests touch no database: the request is refused before the store is
// used. (The package TestMain still starts the Docker test database, so they
// need a Docker-capable host to run.)

func TestDBSimErrorsMapToHTTPStatuses(t *testing.T) {
	for _, c := range []struct {
		err  error
		want int
	}{
		{dbadmin.ErrForbidden, http.StatusForbidden},
		{dbsim.ErrTargetInvalid, http.StatusBadRequest},
		{dbsim.ErrTargetExists, http.StatusConflict},
		{dbsim.ErrTargetNotFound, http.StatusNotFound},
		{dbsim.ErrTargetChanged, http.StatusConflict},
		{dbsim.ErrIdentityCheckSuperseded, http.StatusConflict},
		{fmt.Errorf("wrapped: %w", dbsim.ErrTargetChanged), http.StatusConflict},
		{dbadmin.ErrIdentityCheckUnavailable, http.StatusNotImplemented},
		{errors.New("pq: connection refused to 10.0.0.9"), http.StatusInternalServerError},
	} {
		w := httptest.NewRecorder()
		dbsimFail(w, c.err)
		if w.Code != c.want {
			t.Errorf("%v: got %d want %d", c.err, w.Code, c.want)
		}
		if c.want == http.StatusInternalServerError && strings.Contains(w.Body.String(), "10.0.0.9") {
			t.Errorf("internal error text leaked to the client: %s", w.Body.String())
		}
	}
}

func TestRegisterDBSimTargetRefusesUnknownFieldsSuchAsAPassword(t *testing.T) {
	h := &Handler{}
	for _, body := range []string{
		`{"id":"t1","engine":"postgresql","host":"h","credentialRef":"dbcred:x","expectedIdentity":"1","mode":"client","password":"hunter2"}`,
		`{"id":"t1","engine":"postgresql","host":"h","credentialRef":"dbcred:x","expectedIdentity":"1","mode":"client","user":"u"}`,
		`not json`,
	} {
		w := httptest.NewRecorder()
		h.RegisterDBSimTarget(w, httptest.NewRequest(http.MethodPost, "/api/dbsim-targets", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%q: got %d want 400", body, w.Code)
		}
		if strings.Contains(w.Body.String(), "hunter2") {
			t.Errorf("the rejected password was echoed: %s", w.Body.String())
		}
	}
}

func TestSetDBSimClientModeNeedsAnExplicitBoolean(t *testing.T) {
	h := &Handler{}
	for _, body := range []string{``, `{}`, `{"enabled":"yes"}`, `{"enabled":true,"x":1}`, `[]`} {
		w := httptest.NewRecorder()
		h.SetDBSimClientMode(w, httptest.NewRequest(http.MethodPut, "/api/dbsim/settings/client-mode", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%q: got %d want 400", body, w.Code)
		}
	}
}

func TestDBSimViewClientEligibility(t *testing.T) {
	reg, err := dbsim.TargetRegistration{ID: "t1", Engine: "postgresql", Host: "h.example", CredentialRef: "dbcred:x",
		ExpectedIdentity: "123", Mode: dbsim.ModeClient, AgentID: "0123456789abcdef"}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	rec := dbsim.TargetRecord{TargetRegistration: reg}
	now := time.Now()
	if v := dbsimView(rec, now); v.ClientEligible || v.IdentityCheck.Reasons == nil {
		t.Fatalf("fresh target: %+v", v)
	}
	rec.IdentityCheck = dbsim.IdentityCheckState{Checked: true, Passed: true, At: time.Now(), By: "u"}
	if !dbsimView(rec, now).ClientEligible {
		t.Fatal("a passed check must make a client target eligible")
	}
	// The view uses the injected clock: the same pass is stale 24h later.
	if dbsimView(rec, now.Add(dbsim.DefaultIdentityCheckMaxAge+time.Minute)).ClientEligible {
		t.Fatal("a stale pass must not show as eligible")
	}
}
