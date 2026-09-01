package cloudsink

import (
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// handleGCSUpload mimics Google Cloud Storage's simple media-upload
// request: the object name is a query parameter, not part of the URL path
// or a header.
func handleGCSUpload(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !limiter.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		token := strings.TrimSuffix(r.URL.Query().Get("name"), ".dat")

		r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}

		if tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "cloud-gcs", body)
		}
		w.WriteHeader(http.StatusOK)
	}
}
