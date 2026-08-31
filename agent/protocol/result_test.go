package protocol

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubmitResult_SignsBodyWhenSecretSet(t *testing.T) {
	var gotMAC string
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMAC = r.Header.Get("X-Result-MAC")
		gotBody, _ = io.ReadAll(r.Body)
	}))
	defer server.Close()

	payload := RawRunResult{RunID: "r1", AgentID: "a1"}
	if err := SubmitResult(context.Background(), server.Client(), server.URL, "secret123", payload); err != nil {
		t.Fatalf("SubmitResult: %v", err)
	}
	want := SignBody(gotBody, "secret123")
	if gotMAC != want {
		t.Errorf("X-Result-MAC = %q, want %q", gotMAC, want)
	}
}

func TestSubmitResult_NoSecretOmitsMACHeader(t *testing.T) {
	var gotMAC string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMAC = r.Header.Get("X-Result-MAC")
	}))
	defer server.Close()

	if err := SubmitResult(context.Background(), server.Client(), server.URL, "", RawRunResult{}); err != nil {
		t.Fatalf("SubmitResult: %v", err)
	}
	if gotMAC != "" {
		t.Errorf("X-Result-MAC = %q, want empty when no secret configured", gotMAC)
	}
}

func TestSignBody_DeterministicAndSecretSensitive(t *testing.T) {
	body := []byte(`{"runId":"r1"}`)
	a := SignBody(body, "secret-a")
	b := SignBody(body, "secret-a")
	c := SignBody(body, "secret-b")
	if a != b {
		t.Error("SignBody is not deterministic for the same body+secret")
	}
	if a == c {
		t.Error("SignBody produced the same MAC for two different secrets")
	}
}
