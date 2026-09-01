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

// handleBoxUpload mimics Box's multipart/form-data upload request: an
// "attributes" JSON part (carrying the token as its "name" field) plus a
// "file" part.
func handleBoxUpload(db *pgxpool.Pool) http.HandlerFunc {
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
			w.WriteHeader(http.StatusCreated)
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
			if part.FormName() == "attributes" {
				var attrs struct {
					Name string `json:"name"`
				}
				if json.Unmarshal(data, &attrs) == nil {
					token = strings.TrimSuffix(attrs.Name, ".dat")
				}
			} else if part.FormName() == "file" {
				content = data
			}
		}

		if token != "" && tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "cloud-box", content)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"entries":[{"id":"bas-sim-id","name":"bas-sim"}]}`))
	}
}
