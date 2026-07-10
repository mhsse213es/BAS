package exercise

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFireWebhook_SuccessAndDefaults(t *testing.T) {
	var gotMethod, gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := fireWebhook(context.Background(), "", srv.URL, nil, `{"a":1}`); err != nil {
		t.Fatalf("fireWebhook: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("default method = %q, want POST", gotMethod)
	}
	if gotContentType != "application/json" {
		t.Fatalf("default content-type = %q, want application/json", gotContentType)
	}
}

func TestFireWebhook_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := fireWebhook(context.Background(), "POST", srv.URL, nil, ""); err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestFireWebhook_BadURL(t *testing.T) {
	if err := fireWebhook(context.Background(), "GET", "http://%zz", nil, ""); err == nil {
		t.Fatal("expected request-construction error for malformed URL")
	}
}
