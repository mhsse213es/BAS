package modsecwaf

import (
	"io"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
)

func TestBuildRequest_EmptyPayloadLocation_NoBody(t *testing.T) {
	req, err := BuildRequest("http://localhost:8888", wafcatalog.RequestTemplate{
		Method: "TRACE", Path: "/admin/settings",
	})
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}
	if req.Method != "TRACE" {
		t.Errorf("Method = %q, want TRACE", req.Method)
	}
	if req.URL.String() != "http://localhost:8888/admin/settings" {
		t.Errorf("URL = %q, want http://localhost:8888/admin/settings", req.URL.String())
	}
}

func TestBuildRequest_QueryPayloadLocation_SetsQueryParam(t *testing.T) {
	req, err := BuildRequest("http://localhost:8888", wafcatalog.RequestTemplate{
		Method: "GET", Path: "/search", PayloadLocation: "query:q", Payload: "' UNION SELECT NULL,NULL,NULL--",
	})
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}
	if got := req.URL.Query().Get("q"); got != "' UNION SELECT NULL,NULL,NULL--" {
		t.Errorf("query param q = %q, want the raw SQLi payload", got)
	}
}

func TestBuildRequest_UnsupportedPayloadLocation_Errors(t *testing.T) {
	_, err := BuildRequest("http://localhost:8888", wafcatalog.RequestTemplate{
		Method: "POST", Path: "/upload", PayloadLocation: "header:X-Forwarded-Host", Payload: "evil.example.com",
	})
	if err == nil {
		t.Fatal("BuildRequest: want an error for an unsupported PayloadLocation, got nil")
	}
}

// Review Focus: "body:multipart:<field>" where <field> is not the literal
// "filename" means Payload IS the file's content, sent under a fixed,
// generic filename -- the request must be real multipart/form-data a real
// WAF can parse, not a raw string crammed into the body.
func TestBuildRequest_MultipartFileFieldPayloadLocation_SendsPayloadAsFileContent(t *testing.T) {
	req, err := BuildRequest("http://localhost:8888", wafcatalog.RequestTemplate{
		Method: "POST", Path: "/upload", PayloadLocation: "body:multipart:file",
		Payload: "<?php system($_GET['cmd']); ?>",
	})
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}
	mr, err := req.MultipartReader()
	if err != nil {
		t.Fatalf("MultipartReader: %v", err)
	}
	part, err := mr.NextPart()
	if err != nil {
		t.Fatalf("NextPart: %v", err)
	}
	if part.FormName() != "file" {
		t.Errorf("FormName = %q, want %q", part.FormName(), "file")
	}
	content, err := io.ReadAll(part)
	if err != nil {
		t.Fatalf("reading part: %v", err)
	}
	if string(content) != "<?php system($_GET['cmd']); ?>" {
		t.Errorf("content = %q, want the raw payload", content)
	}
}

// Review Focus: "body:multipart:filename" means Payload IS the filename
// itself (e.g. a path-traversal string) -- the attack is in the filename,
// not the content, so the content is a fixed, inert placeholder and the
// raw Payload must appear verbatim on the wire as the part's filename.
// Asserted against the raw Content-Disposition header, not Go's own
// Part.FileName() accessor -- that method applies filepath.Base() as a
// client-side safety convenience, which would defang exactly the
// traversal payload this test exists to prove travels unmodified; a real
// WAF inspects the raw header, not Go's sanitized view of it.
func TestBuildRequest_MultipartFilenameFieldPayloadLocation_SendsPayloadAsFilename(t *testing.T) {
	req, err := BuildRequest("http://localhost:8888", wafcatalog.RequestTemplate{
		Method: "POST", Path: "/upload", PayloadLocation: "body:multipart:filename",
		Payload: "../../../../etc/cron.d/evil",
	})
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if !strings.Contains(string(raw), `filename="../../../../etc/cron.d/evil"`) {
		t.Errorf("raw multipart body missing the literal traversal filename, got: %s", raw)
	}
}
