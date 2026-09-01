package cloudsink

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOneDrivePut_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2"
		seedToken(t, pool, token, "run-onedrive-1", "T1567.002")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		body := []byte("[BAS-SIM-DLP] test payload")
		uri := srv.URL + "/graph/v1.0/me/drive/root:/" + token + ".dat:/content"
		req, _ := http.NewRequest(http.MethodPut, uri, bytes.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "cloud-onedrive", len(body))
	})
}

func TestOneDrivePut_UnmatchedTokenStillSucceedsNoReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		uri := srv.URL + "/graph/v1.0/me/drive/root:/never-issued.dat:/content"
		req, _ := http.NewRequest(http.MethodPut, uri, bytes.NewReader([]byte("x")))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200 even for an unmatched token", resp.StatusCode)
		}
		assertNoReceipt(t, pool, "never-issued")
	})
}
