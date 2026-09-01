package webhooksink

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const teamsPath = "/teams/webhookb2/00000000-0000-0000-0000-000000000000/IncomingWebhook/11111111111111111111111111111111/22222222-2222-2222-2222-222222222222"

func TestTeamsWebhook_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1"
		seedToken(t, pool, token, "run-teams-1", "T1567.004")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		text := token + "\n[BAS-SIM-DLP] test payload"
		body := slackTeamsBody(t, text)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+teamsPath, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "webhook-teams", len(body))
	})
}
