package cloudsink

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// handleDropboxUpload mimics Dropbox's /2/files/upload request: the
// destination path is a JSON object in the Dropbox-API-Arg header, not the
// URL or body. A missing/malformed header is treated identically to an
// unmatched token -- still a 200, never a receipt.
func handleDropboxUpload(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !limiter.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}

		var apiArg struct {
			Path string `json:"path"`
		}
		token := ""
		if err := json.Unmarshal([]byte(r.Header.Get("Dropbox-API-Arg")), &apiArg); err == nil {
			token = strings.TrimSuffix(strings.TrimPrefix(apiArg.Path, "/"), ".dat")
		}

		if token != "" && tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "cloud-dropbox", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"bas-sim","id":"bas-sim-id"}`))
	}
}
