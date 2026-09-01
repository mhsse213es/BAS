package webhooksink

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// handleGitLabSnippet mimics GitLab's POST /api/v4/snippets request: a
// "file_name" field carries the token. The PRIVATE-TOKEN header's value
// is never validated -- same presence-only fidelity rule as the GitHub
// handler above.
func handleGitLabSnippet(db *pgxpool.Pool) http.HandlerFunc {
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
			FileName string `json:"file_name"`
		}
		token := ""
		if json.Unmarshal(body, &payload) == nil {
			token = strings.TrimSuffix(payload.FileName, ".dat")
		}

		if token != "" && tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "coderepo-gitlab", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":1,"web_url":"https://gitlab.example/-/snippets/bas-sim"}`))
	}
}
