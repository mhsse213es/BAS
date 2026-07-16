package exercise

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSMSInjector_PostsPerRecipient(t *testing.T) {
	var got []map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]string
		_ = json.Unmarshal(b, &m)
		got = append(got, m)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	inj := NewSMSInjector(SMSGatewayConfig{URL: srv.URL, From: "BAS"})
	res, err := inj.Send(context.Background(), []string{"+15550001", "+15550002"}, "hello")
	if err != nil {
		t.Fatal(err)
	}
	if res["sent"] != 2 {
		t.Fatalf("want 2 sent, got %v", res["sent"])
	}
	if len(got) != 2 || got[0]["body"] != "hello" || got[0]["from"] != "BAS" {
		t.Fatalf("payload wrong: %+v", got)
	}
}

func TestSMSInjector_Unconfigured(t *testing.T) {
	inj := NewSMSInjector(SMSGatewayConfig{})
	if _, err := inj.Send(context.Background(), []string{"x"}, "y"); err == nil {
		t.Fatal("want error when URL empty")
	}
}

func TestSlackInjector_PostsText(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	inj := NewSlackInjector(srv.URL)
	if _, err := inj.Send(context.Background(), "alert!"); err != nil {
		t.Fatal(err)
	}
	if body["text"] != "alert!" {
		t.Fatalf("want text=alert!, got %v", body["text"])
	}
}

func TestTeamsInjector_Unconfigured(t *testing.T) {
	inj := NewTeamsInjector("")
	if _, err := inj.Send(context.Background(), "x"); err == nil {
		t.Fatal("want error when webhook empty")
	}
}

func TestSlackInjector_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	inj := NewSlackInjector(srv.URL)
	if _, err := inj.Send(context.Background(), "x"); err == nil {
		t.Fatal("want error on HTTP 500")
	}
}
