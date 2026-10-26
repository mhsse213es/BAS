package protocol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubmitCSRWithToken_SendsTheTokenHeaderOnlyWhenGiven(t *testing.T) {
	var gotToken, gotSecret string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Enrollment-Token")
		gotSecret = r.Header.Get("X-Agent-Token")
		w.Write([]byte(`{"certPem":"c","caPem":"a","expiresAt":"2030-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	if _, err := SubmitCSRWithToken(context.Background(), srv.Client(), srv.URL, "secret", "bas_enr_x", CSRRequest{AgentID: "a"}); err != nil {
		t.Fatal(err)
	}
	if gotToken != "bas_enr_x" || gotSecret != "secret" {
		t.Errorf("token=%q secret=%q, want both sent", gotToken, gotSecret)
	}

	if _, err := SubmitCSR(context.Background(), srv.Client(), srv.URL, "secret", CSRRequest{AgentID: "a"}); err != nil {
		t.Fatal(err)
	}
	if gotToken != "" {
		t.Errorf("SubmitCSR must send no enrolment token, got %q", gotToken)
	}
}
