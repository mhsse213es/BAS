package webhooksink

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// handleSlackWebhook mimics a Slack Incoming Webhook request: JSON body
// {"text": "..."}, no separate auth header (the webhook URL itself is the
// secret in real Slack, matching this route's own path shape). The token
// is the first line of "text"; the rest is the synthetic record.
func handleSlackWebhook(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !limiter.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, MaxPayloadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}

		var payload struct {
			Text string `json:"text"`
		}
		token := ""
		if json.Unmarshal(body, &payload) == nil {
			token = strings.SplitN(payload.Text, "\n", 2)[0]
		}

		if token != "" && tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "webhook-slack", body)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}
