package cloudsink

import (
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// handleGDriveUpload mimics Google Drive's multipart/related upload
// request: a JSON metadata part (carrying the token as its "name" field)
// followed by the raw content part.
func handleGDriveUpload(db *pgxpool.Pool) http.HandlerFunc {
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

		mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
			w.WriteHeader(http.StatusOK)
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])

		var token string
		var content []byte
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			data, _ := io.ReadAll(part)
			if strings.Contains(part.Header.Get("Content-Type"), "application/json") {
				var meta struct {
					Name string `json:"name"`
				}
				if json.Unmarshal(data, &meta) == nil {
					token = strings.TrimSuffix(meta.Name, ".dat")
				}
			} else {
				content = data
			}
		}

		if token != "" && tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "cloud-gdrive", content)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"bas-sim-id","name":"bas-sim"}`))
	}
}
