package aisink

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const connectorIngestionPath = "/v1.0/external/connections/bas-sim-connection/items/bas-sim-item"

func TestConnectorIngestion_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2"
		seedToken(t, pool, token, "run-ai-connector-1", "T1567")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		content := token + "\n[BAS-SIM-DLP] test payload"
		body := connectorBody(t, content)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+connectorIngestionPath, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer bas-sim-irrelevant-key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("status = %d, want 201", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "ai-connector-ingestion", len(body))
	})
}

func TestConnectorIngestion_UnmatchedTokenStillSucceedsNoReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		body := connectorBody(t, "never-issued-token\nunrelated body")
		req, _ := http.NewRequest(http.MethodPost, srv.URL+connectorIngestionPath, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("status = %d, want 201 even for an unmatched token", resp.StatusCode)
		}
		assertNoReceipt(t, pool, "never-issued-token")
	})
}

func TestConnectorIngestion_MalformedBodyStillSucceedsNoReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		req, _ := http.NewRequest(http.MethodPost, srv.URL+connectorIngestionPath, bytes.NewReader([]byte("not json at all")))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("status = %d, want 201 even for a malformed body", resp.StatusCode)
		}
	})
}

func TestConnectorIngestion_OversizedBodyRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		tooBig := connectorBody(t, string(bytes.Repeat([]byte("x"), MaxPayloadBytes+1024)))
		req, _ := http.NewRequest(http.MethodPost, srv.URL+connectorIngestionPath, bytes.NewReader(tooBig))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			t.Error("a body exceeding MaxPayloadBytes should not return a success status")
		}
	})
}

func TestConnectorIngestion_RetryWithSameTokenRecordsBothReceipts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3"
		seedToken(t, pool, token, "run-ai-connector-retry", "T1567")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		body := connectorBody(t, token+"\nretry payload")
		for i := 0; i < 2; i++ {
			req, _ := http.NewRequest(http.MethodPost, srv.URL+connectorIngestionPath, bytes.NewReader(body))
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
