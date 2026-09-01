package cloudsink

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDropboxUpload_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3"
		seedToken(t, pool, token, "run-dropbox-1", "T1567.002")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		body := []byte("[BAS-SIM-DLP] test payload")
		apiArg, _ := json.Marshal(map[string]string{"path": "/" + token + ".dat", "mode": "add"})
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/dropbox/2/files/upload", bytes.NewReader(body))
		req.Header.Set("Dropbox-API-Arg", string(apiArg))
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "cloud-dropbox", len(body))
	})
}

func TestDropboxUpload_MalformedAPIArgStillSucceedsNoReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/dropbox/2/files/upload", bytes.NewReader([]byte("x")))
		req.Header.Set("Dropbox-API-Arg", "not valid json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200 even for a malformed/unmatched Dropbox-API-Arg", resp.StatusCode)
		}
	})
}
