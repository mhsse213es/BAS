package cloudsink

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAzureBlobPut_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1"
		seedToken(t, pool, token, "run-azureblob-1", "T1567.002")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		body := []byte("[BAS-SIM-DLP] test payload")
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/azureblob/bas-sim-container/"+token+".dat", bytes.NewReader(body))
		req.Header.Set("x-ms-version", "2021-08-06")
		req.Header.Set("x-ms-blob-type", "BlockBlob")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("status = %d, want 201 (matching real Azure Blob PUT Blob's own success code)", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "cloud-azureblob", len(body))
	})
}
