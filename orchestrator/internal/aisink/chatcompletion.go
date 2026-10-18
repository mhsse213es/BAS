package aisink

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// handleChatCompletion mimics an OpenAI-compatible POST
// /v1/chat/completions request: a "messages" array whose first entry's
// "content" carries the token as its first line, the rest being the
// synthetic sensitive record -- matching the real-world shape of a user
// pasting sensitive data into a chat prompt. The Authorization header's
// value is never validated, same posture as every sibling channel: this
// tests whether DLP inspected the outbound traffic, not whether the
// caller authenticated.
func handleChatCompletion(db *pgxpool.Pool) http.HandlerFunc {
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
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		token := ""
		if json.Unmarshal(body, &payload) == nil && len(payload.Messages) > 0 {
			token = strings.SplitN(payload.Messages[0].Content, "\n", 2)[0]
		}

		if token != "" && tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "ai-chat-completion", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}
}
