package cloudsink

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func gdriveMultipartBody(boundary, metadataJSON, content string) string {
	return fmt.Sprintf(
		"--%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n%s\r\n--%s\r\nContent-Type: text/plain\r\n\r\n%s\r\n--%s--",
		boundary, metadataJSON, boundary, content, boundary,
	)
}

func TestGDriveUpload_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5"
		seedToken(t, pool, token, "run-gdrive-1", "T1567.002")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		boundary := "bas-sim-boundary"
		metadata := fmt.Sprintf(`{"name":"%s.dat","mimeType":"text/plain"}`, token)
		content := "[BAS-SIM-DLP] test payload"
		bodyStr := gdriveMultipartBody(boundary, metadata, content)

		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/gdrive/upload/drive/v3/files", bytes.NewReader([]byte(bodyStr)))
		req.Header.Set("Content-Type", "multipart/related; boundary="+boundary)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "cloud-gdrive", len(content))
	})
}
