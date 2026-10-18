package aisink

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const chatCompletionPath = "/v1/chat/completions"

func TestChatCompletion_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718"
		seedToken(t, pool, token, "run-ai-chat-1", "T1567")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		content := token + "\n[BAS-SIM-DLP] test payload"
		body := chatBody(t, content)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+chatCompletionPath, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer bas-sim-irrelevant-key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "ai-chat-completion", len(body))
	})
}

func TestChatCompletion_UnmatchedTokenStillSucceedsNoReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		body := chatBody(t, "never-issued-token\nunrelated body")
		req, _ := http.NewRequest(http.MethodPost, srv.URL+chatCompletionPath, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200 even for an unmatched token", resp.StatusCode)
		}
		assertNoReceipt(t, pool, "never-issued-token")
	})
}

func TestChatCompletion_MalformedBodyStillSucceedsNoReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		req, _ := http.NewRequest(http.MethodPost, srv.URL+chatCompletionPath, bytes.NewReader([]byte("not json at all")))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200 even for a malformed body", resp.StatusCode)
		}
	})
}

func TestChatCompletion_OversizedBodyRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		tooBig := chatBody(t, string(bytes.Repeat([]byte("x"), MaxPayloadBytes+1024)))
		req, _ := http.NewRequest(http.MethodPost, srv.URL+chatCompletionPath, bytes.NewReader(tooBig))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Error("a body exceeding MaxPayloadBytes should not return 200")
		}
	})
}

func TestChatCompletion_RetryWithSameTokenRecordsBothReceipts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1"
		seedToken(t, pool, token, "run-ai-chat-retry", "T1567")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		body := chatBody(t, token+"\nretry payload")
		for i := 0; i < 2; i++ {
			req, _ := http.NewRequest(http.MethodPost, srv.URL+chatCompletionPath, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("POST %d: %v", i, err)
			}
			resp.Body.Close()
		}

		deadline := time.Now().Add(5 * time.Second)
		for {
			if countReceipts(t, pool, token) >= 2 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("expected 2 receipts for retried token, got %d", countReceipts(t, pool, token))
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
}
