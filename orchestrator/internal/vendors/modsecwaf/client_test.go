package modsecwaf

import (
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
		Method: "POST", Path: "/upload", PayloadLocation: "body:multipart:file", Payload: "<jpeg bytes>",
	})
	if err == nil {
		t.Fatal("BuildRequest: want an error for an unsupported PayloadLocation, got nil")
	}
}
