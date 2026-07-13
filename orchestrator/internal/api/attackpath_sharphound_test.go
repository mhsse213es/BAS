package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// BloodHound v4 fixture files, matching internal/attackpath/sharphound_test.go's
// own fixtures (trimmed to the fields the parser reads) so a successful upload
// exercises the real ParseSharpHoundZip path rather than a hand-rolled shape.
const shTestComputers = `{"meta":{"type":"computers","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-1001","Properties":{"name":"DC01.CORP.LOCAL","domain":"CORP.LOCAL"},
   "LocalAdmins":{"Results":[]},"Sessions":{"Results":[]}}
]}`
const shTestUsers = `{"meta":{"type":"users","count":0},"data":[]}`
const shTestGroups = `{"meta":{"type":"groups","count":0},"data":[]}`

func buildSharpHoundZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{
		"20260619_computers.json": shTestComputers,
		"20260619_users.json":     shTestUsers,
		"20260619_groups.json":    shTestGroups,
	} {
		f, _ := zw.Create(name)
		f.Write([]byte(body))
	}
	zw.Close()
	return buf.Bytes()
}

func sharpHoundReq(agentID, hostname string, body []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/attackpath/sharphound", bytes.NewReader(body))
	q := req.URL.Query()
	if agentID != "" {
		q.Set("agentId", agentID)
	}
	if hostname != "" {
		q.Set("hostname", hostname)
	}
	req.URL.RawQuery = q.Encode()
	return req
}

func TestSubmitAttackPathSharpHound_Unauthorized(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool).WithAgentSecret("shh")
		rec := httptest.NewRecorder()
		h.SubmitAttackPathSharpHound(rec, sharpHoundReq("sh-agent", "DC01", buildSharpHoundZip(t)))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}

func TestSubmitAttackPathSharpHound_MissingAgentID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		rec := httptest.NewRecorder()
		h.SubmitAttackPathSharpHound(rec, sharpHoundReq("", "DC01", buildSharpHoundZip(t)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestSubmitAttackPathSharpHound_EmptyBody(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		rec := httptest.NewRecorder()
		h.SubmitAttackPathSharpHound(rec, sharpHoundReq("sh-agent", "DC01", nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestSubmitAttackPathSharpHound_InvalidZip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		rec := httptest.NewRecorder()
		h.SubmitAttackPathSharpHound(rec, sharpHoundReq("sh-agent", "DC01", []byte("not a zip")))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

// TestSubmitAttackPathSharpHound_Success drives a real BloodHound-shaped zip
// through ParseSharpHoundZip (already exhaustively unit-tested at the package
// level) and confirms the HTTP wiring: response shape, source tagging, and
// that it lands in attackpath_collections under source='sharphound'.
func TestSubmitAttackPathSharpHound_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		rec := httptest.NewRecorder()
		h.SubmitAttackPathSharpHound(rec, sharpHoundReq("sh-success-agent", "DC01", buildSharpHoundZip(t)))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if out["source"] != "sharphound" || out["agentId"] != "sh-success-agent" {
			t.Fatalf("out = %+v, want source=sharphound agentId=sh-success-agent", out)
		}

		var storedSource string
		if err := pool.QueryRow(context.Background(),
			`SELECT source FROM attackpath_collections WHERE agent_id=$1 AND source='sharphound'`,
			"sh-success-agent").Scan(&storedSource); err != nil {
			t.Fatalf("read stored collection: %v", err)
		}
	})
}
