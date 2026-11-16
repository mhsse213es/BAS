package cigate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
)

func guarded(verify Verifier) http.Handler {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	return Auth(verify)(ok)
}

func call(h http.Handler, authz string) int {
	req := httptest.NewRequest(http.MethodPost, "/api/ci/validations", strings.NewReader("{}"))
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestCIAuth_RefusesEverythingButAnActiveCIToken(t *testing.T) {
	good, _ := NewToken()
	verify := func(_ context.Context, tok string) (TokenInfo, error) {
		if tok == good {
			return TokenInfo{ID: "1"}, nil
		}
		return TokenInfo{}, ErrNoToken
	}
	h := guarded(verify)
	cases := map[string]int{
		"":                      http.StatusUnauthorized, // no credential
		"Bearer ":               http.StatusUnauthorized,
		"Basic abc":             http.StatusUnauthorized,
		"Bearer eyJhbGciOi.x.y": http.StatusUnauthorized, // a user session JWT is refused here
		"Bearer " + good + "x":  http.StatusUnauthorized, // wrong shape
		"Bearer bas_ci_" + strings.Repeat("0", 64): http.StatusUnauthorized, // well-formed but unknown
		"Bearer " + good: http.StatusTeapot, // active token gets through
	}
	for authz, want := range cases {
		if got := call(h, authz); got != want {
			t.Errorf("Authorization %q: status %d, want %d", authz, got, want)
		}
	}
}

func TestStartValidation_NoLabAgentIsUnavailableNotSilent(t *testing.T) {
	h := NewHandler(NewService(nil, nil, nil, ""), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/ci/validations", strings.NewReader(`{"contentId":"x"}`))
	rec := httptest.NewRecorder()
	h.StartValidation(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 when no factory lab agent is set", rec.Code)
	}
}

func TestStartValidation_RejectsBadBody(t *testing.T) {
	h := NewHandler(NewService(nil, nil, nil, "lab"), nil)
	for _, body := range []string{"", "not json", `{"contentId":""}`} {
		req := httptest.NewRequest(http.MethodPost, "/api/ci/validations", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.StartValidation(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status %d, want 400", body, rec.Code)
		}
	}
}

func TestCreateToken_RefusesBlankName(t *testing.T) {
	h := NewHandler(nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/ci-tokens", strings.NewReader(`{"name":"   "}`))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "u"}))
	rec := httptest.NewRecorder()
	h.CreateToken(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 for a blank name", rec.Code)
	}
}

func TestStatusFor_RunningHasNoVerdictAndFinishedMapsToOneVerdict(t *testing.T) {
	if st := statusFor("r1", "running", []byte("[]")); st.State != "running" || st.Verdict != "" {
		t.Fatalf("running run: %+v, want no verdict yet", st)
	}
	pass := statusFor("r2", "completed", []byte(`[{"result":"pass"}]`))
	if pass.State != "completed" || pass.Verdict != "pass" {
		t.Fatalf("passing run: %+v, want completed/pass", pass)
	}
	fail := statusFor("r3", "completed", []byte(`[{"result":"pass"},{"result":"error","executionFailure":{"owner":"audspect"}}]`))
	if fail.Verdict != "fail" {
		t.Fatalf("failing run: %+v, want fail", fail)
	}
	none := statusFor("r4", "completed", []byte(`[{"result":"error","executionFailure":{"owner":"environment"}}]`))
	if none.Verdict == "pass" {
		t.Fatalf("environment-only run must never read as pass: %+v", none)
	}
}
