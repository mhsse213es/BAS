package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networktopology"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func validTopologyImportBody() map[string]any {
	return map[string]any{
		"sourceType": "manual-declared",
		"zones":      []map[string]any{{"name": "dmz", "cidrs": []string{"10.0.1.0/24"}}, {"name": "internal", "cidrs": []string{"10.0.2.0/24"}}},
		"edges":      []map[string]any{{"fromZone": "dmz", "toZone": "internal"}},
	}
}

func networkTopologyImportReq(t *testing.T, pool *pgxpool.Pool, body map[string]any) *http.Request {
	t.Helper()
	userID := seedUser(t, pool, fmt.Sprintf("nettopo-op-%d", time.Now().UnixNano()), "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	return authedRequest(t, http.MethodPost, "/api/network-topology-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
}

func TestCreateNetworkTopologyImport_ValidImportPersists(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := networkTopologyImportReq(t, pool, validTopologyImportBody())
		rec := callAuthed(h.CreateNetworkTopologyImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp networktopology.TopologyImport
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.ID == "" {
			t.Fatal("want non-empty id")
		}
	})
}

func TestCreateNetworkTopologyImport_ZeroEdgesAllowed(t *testing.T) {
	// A topology may legitimately declare zones with no mapped routes
	// yet -- "topology may be unknown or partially modeled" per the
	// spec. Unlike Phase 2A's PolicyImport, edges are not required.
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validTopologyImportBody()
		body["edges"] = []map[string]any{}
		req := networkTopologyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkTopologyImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkTopologyImport_EmptyZonesRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validTopologyImportBody()
		body["zones"] = []map[string]any{}
		req := networkTopologyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkTopologyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkTopologyImport_DuplicateZoneNameRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validTopologyImportBody()
		body["zones"] = []map[string]any{{"name": "dmz", "cidrs": []string{"10.0.1.0/24"}}, {"name": "dmz", "cidrs": []string{"10.0.9.0/24"}}}
		req := networkTopologyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkTopologyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkTopologyImport_InvalidCIDRRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validTopologyImportBody()
		body["zones"] = []map[string]any{{"name": "dmz", "cidrs": []string{"not-a-cidr"}}}
		req := networkTopologyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkTopologyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkTopologyImport_EdgeReferencingUnknownZoneRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validTopologyImportBody()
		body["edges"] = []map[string]any{{"fromZone": "dmz", "toZone": "does-not-exist"}}
		req := networkTopologyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkTopologyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkTopologyImport_SelfLoopEdgeRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validTopologyImportBody()
		body["edges"] = []map[string]any{{"fromZone": "dmz", "toZone": "dmz"}}
		req := networkTopologyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkTopologyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s -- a self-loop edge is malformed input", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkTopologyImport_OversizedBodyRejectedBeforeFullDecode(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "nettopo-op-oversize", "pw12345678", string(auth.RoleAnalyst), true)
		oversized := []byte(`{"sourceType":"` + strings.Repeat("x", maxNetworkTopologyImportRequestBytes+1) + `"}`)
		req := authedRequest(t, http.MethodPost, "/api/network-topology-imports", bytes.NewReader(oversized), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateNetworkTopologyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkTopologyImport_ImportedByIsServerControlled(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "nettopo-op-spoof", "pw12345678", string(auth.RoleAnalyst), true)
		body := validTopologyImportBody()
		body["importedBy"] = "spoofed-user"
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/network-topology-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateNetworkTopologyImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp networktopology.TopologyImport
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		got, err := db.GetNetworkTopologyImport(context.Background(), pool, resp.ID)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if got.ImportedBy != userID {
			t.Fatalf("ImportedBy = %q, want %q (the authenticated caller, not the spoofed body value)", got.ImportedBy, userID)
		}
	})
}

func TestListAndGetNetworkTopologyImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := networkTopologyImportReq(t, pool, validTopologyImportBody())
		createRec := callAuthed(h.CreateNetworkTopologyImport, req)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create status = %d, body = %s", createRec.Code, createRec.Body.String())
		}
		var created networktopology.TopologyImport
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create: %v", err)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/network-topology-imports", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListNetworkTopologyImports, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}

		getReq := authedRequest(t, http.MethodGet, "/api/network-topology-imports/"+created.ID, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", created.ID)
		getRec := callAuthed(h.GetNetworkTopologyImport, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
	})
}
