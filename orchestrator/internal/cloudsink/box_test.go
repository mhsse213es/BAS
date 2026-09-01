package cloudsink

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func boxMultipartBody(boundary, attributesJSON, filename, content string) string {
	return fmt.Sprintf(
		"--%s\r\nContent-Disposition: form-data; name=\"attributes\"\r\n\r\n%s\r\n"+
			"--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n--%s--",
		boundary, attributesJSON, boundary, filename, content, boundary,
	)
}

func TestBoxUpload_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "0718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f6"
		seedToken(t, pool, token, "run-box-1", "T1567.002")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		boundary := "bas-sim-boundary"
		attrs := fmt.Sprintf(`{"name":"%s.dat","parent":{"id":"0"}}`, token)
		content := "[BAS-SIM-DLP] test payload"
		bodyStr := boxMultipartBody(boundary, attrs, token+".dat", content)

		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/box/2.0/files/content", bytes.NewReader([]byte(bodyStr)))
		req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("status = %d, want 201 (matching real Box upload's own success code)", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "cloud-box", len(content))
	})
}
