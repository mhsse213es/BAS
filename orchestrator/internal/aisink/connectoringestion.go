package aisink

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// handleConnectorIngestion mimics a Microsoft Graph connector
// content-ingestion request: a "content.value" field carrying the token
// as its first line, the rest being the synthetic sensitive record.
// Authorization is never validated, same posture as handleChatCompletion.
func handleConnectorIngestion(db *pgxpool.Pool) http.HandlerFunc {
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
			Content struct {
				Value string `json:"value"`
			} `json:"content"`
		}
		token := ""
		if json.Unmarshal(body, &payload) == nil {
			token = strings.SplitN(payload.Content.Value, "\n", 2)[0]
		}

		if token != "" && tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "ai-connector-ingestion", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"bas-sim-item"}`))
	}
}
