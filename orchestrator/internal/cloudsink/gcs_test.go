package cloudsink

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestGCSUpload_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4"
		seedToken(t, pool, token, "run-gcs-1", "T1567.002")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		body := []byte("[BAS-SIM-DLP] test payload")
		uri := srv.URL + "/gcs/upload/storage/v1/b/bas-sim-bucket/o?uploadType=media&name=" + token + ".dat"
		req, _ := http.NewRequest(http.MethodPost, uri, bytes.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "cloud-gcs", len(body))
	})
}
