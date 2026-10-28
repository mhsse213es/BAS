package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The sink used to decode every body as JSON. A browser uploads a file as multipart/form-data and a form posts
// urlencoded fields, so the sink now reads those too. These tests run without a database: parseSinkRequest is pure.

func parse(t *testing.T, r *http.Request) dlpSinkRequest {
	t.Helper()
	return parseSinkRequest(httptest.NewRecorder(), r)
}

func TestParseSinkRequest_JSONIsUnchanged(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/dlp/sink", strings.NewReader(`{"token":"T1","payload":"P1","channel":"https-post"}`))
	r.Header.Set("Content-Type", "application/json")
	got := parse(t, r)
	if got.Token != "T1" || got.Payload != "P1" || got.Channel != "https-post" {
		t.Errorf("got %+v", got)
	}
}

func TestParseSinkRequest_JSONWithoutAContentTypeStillWorks(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/dlp/sink", strings.NewReader(`{"token":"T2","payload":"P2","channel":"c"}`))
	if got := parse(t, r); got.Token != "T2" || got.Payload != "P2" {
		t.Errorf("legacy client with no Content-Type: got %+v", got)
	}
}

func TestParseSinkRequest_JSONSentWithATextContentTypeStillWorks(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/dlp/sink", strings.NewReader(`{"token":"T3","payload":"P3","channel":"c"}`))
	r.Header.Set("Content-Type", "text/plain")
	if got := parse(t, r); got.Token != "T3" || got.Payload != "P3" {
		t.Errorf("JSON body under text/plain must still be read as before: got %+v", got)
	}
}

func TestParseSinkRequest_FormFields(t *testing.T) {
	form := url.Values{"token": {"TF"}, "payload": {"a=b&c d"}, "channel": {"browser-form"}}
	r := httptest.NewRequest(http.MethodPost, "/api/dlp/sink", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	got := parse(t, r)
	if got.Token != "TF" || got.Payload != "a=b&c d" || got.Channel != "browser-form" {
		t.Errorf("got %+v", got)
	}
}

func multipartRequest(t *testing.T, fields map[string]string, fileField, fileName, fileContent string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if fileField != "" {
		fw, err := mw.CreateFormFile(fileField, fileName)
		if err != nil {
			t.Fatal(err)
		}
		fw.Write([]byte(fileContent))
	}
	mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/api/dlp/sink", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

func TestParseSinkRequest_MultipartFileUploadTakesTheFileAsThePayload(t *testing.T) {
	r := multipartRequest(t, map[string]string{"token": "TM", "channel": "browser-upload"}, "payload", "record.csv", "CustomerID,PAN\nBAS-SIM-SINK,ABCDE1234F")
	got := parse(t, r)
	if got.Token != "TM" || got.Channel != "browser-upload" {
		t.Errorf("token or channel wrong: %+v", got)
	}
	if got.Payload != "CustomerID,PAN\nBAS-SIM-SINK,ABCDE1234F" {
		t.Errorf("payload = %q, want the uploaded file's bytes", got.Payload)
	}
}

func TestParseSinkRequest_MultipartPlainFieldPayload(t *testing.T) {
	r := multipartRequest(t, map[string]string{"token": "TM2", "payload": "inline text", "channel": "c"}, "", "", "")
	if got := parse(t, r); got.Token != "TM2" || got.Payload != "inline text" {
		t.Errorf("got %+v", got)
	}
}

func TestParseSinkRequest_RawBodyTypesUseHeadersForTokenAndChannel(t *testing.T) {
	for _, ct := range []string{"text/plain", "text/csv", "application/xml", "text/xml", "application/octet-stream", "text/html"} {
		r := httptest.NewRequest(http.MethodPost, "/api/dlp/sink", strings.NewReader("raw,record,body"))
		r.Header.Set("Content-Type", ct)
		r.Header.Set("X-Sink-Token", "TR")
		r.Header.Set("X-Sink-Channel", "raw-"+ct)
		got := parse(t, r)
		if got.Token != "TR" || got.Payload != "raw,record,body" || got.Channel != "raw-"+ct {
			t.Errorf("%s: got %+v", ct, got)
		}
	}
}

func TestParseSinkRequest_OversizedBodyIsCappedNotRejected(t *testing.T) {
	huge := strings.Repeat("A", sinkMaxBody+5000)
	r := httptest.NewRequest(http.MethodPost, "/api/dlp/sink", strings.NewReader(huge))
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("X-Sink-Token", "TBIG")
	got := parse(t, r)
	if got.Token != "TBIG" {
		t.Errorf("token lost on an oversized body: %+v", got)
	}
	if len(got.Payload) > sinkMaxBody {
		t.Errorf("payload length %d exceeds the cap %d", len(got.Payload), sinkMaxBody)
	}
}

func TestParseSinkRequest_GarbageNeverPanicsAndYieldsNoToken(t *testing.T) {
	for _, ct := range []string{"multipart/form-data; boundary=zzz", "application/json", "application/x-www-form-urlencoded", "text/plain", ""} {
		r := httptest.NewRequest(http.MethodPost, "/api/dlp/sink", strings.NewReader("\x00\x01 not valid for any format"))
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		if got := parse(t, r); got.Token != "" {
			t.Errorf("%q: garbage produced a token %q", ct, got.Token)
		}
	}
}

func TestParseSinkRequest_HeaderTokenWinsOverABodyToken(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/dlp/sink", strings.NewReader(`{"token":"BODY","payload":"p"}`))
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("X-Sink-Token", "HEADER")
	if got := parse(t, r); got.Token != "HEADER" {
		t.Errorf("token = %q, want the header's value", got.Token)
	}
}

// End to end: a browser-style multipart upload leaves a receipt whose hash and size are those of the uploaded file.
func TestDLPSink_MultipartUploadRecordsAReceiptForTheFileBytes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		const content = "[BAS-SIM-DLP] browser upload record"
		r := multipartRequest(t, map[string]string{"token": "tok-browser-upload", "channel": "browser-upload"}, "payload", "record.csv", content)
		r.RemoteAddr = "10.0.0.9:50000"
		rec := httptest.NewRecorder()
		h.DLPSink(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		var hash, channel string
		var size int
		if err := pool.QueryRow(context.Background(),
			`SELECT payload_hash, channel, payload_size FROM dlp_sink_receipts WHERE token = 'tok-browser-upload'`).Scan(&hash, &channel, &size); err != nil {
			t.Fatalf("no receipt recorded: %v", err)
		}
		sum := sha256.Sum256([]byte(content))
		if hash != hex.EncodeToString(sum[:]) || size != len(content) || channel != "browser-upload" {
			t.Errorf("receipt hash=%s size=%d channel=%s, want hash of the file, size %d, channel browser-upload", hash, size, channel, len(content))
		}
	})
}
