package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/jackc/pgx/v5/pgxpool"
)

func assetTagReq(t attackpath.AssetTag) *http.Request {
	b, _ := json.Marshal(t)
	return httptest.NewRequest(http.MethodPost, "/api/attackpath/assets", bytes.NewReader(b))
}

func TestGetAttackPathAssets_EmptyGraph(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetAttackPathAssets(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var out struct {
			Assets []attackpath.AssetTag `json:"assets"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out.Assets) != 0 {
			t.Fatalf("expected 0 assets, got %d", len(out.Assets))
		}
	})
}

func TestSetAttackPathAsset_MissingHostKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		rec := httptest.NewRecorder()
		h.SetAttackPathAsset(rec, assetTagReq(attackpath.AssetTag{CrownJewel: "ERP"}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestSetAttackPathAsset_MalformedJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader([]byte(`{"hostKey":`)))
		rec := httptest.NewRecorder()
		h.SetAttackPathAsset(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

// TestSetAttackPathAsset_UpsertThenClear pins the tag lifecycle: setting a
// non-empty tag persists it (normalized host key), and a follow-up call with
// every field empty/false deletes the row rather than storing an empty tag.
func TestSetAttackPathAsset_UpsertThenClear(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		setRec := httptest.NewRecorder()
		h.SetAttackPathAsset(setRec, assetTagReq(attackpath.AssetTag{
			HostKey: "  filesrv01.corp.local  ", CrownJewel: "FileServer", Segment: "prod", HighValue: true,
		}))
		if setRec.Code != http.StatusOK {
			t.Fatalf("set: status = %d, body = %s", setRec.Code, setRec.Body.String())
		}
		var n int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM attackpath_asset_tags WHERE host_key='FILESRV01'`).Scan(&n)
		if n != 1 {
			t.Fatalf("expected 1 normalized row FILESRV01, found %d", n)
		}

		clearRec := httptest.NewRecorder()
		h.SetAttackPathAsset(clearRec, assetTagReq(attackpath.AssetTag{HostKey: "filesrv01.corp.local"}))
		var out map[string]any
		json.Unmarshal(clearRec.Body.Bytes(), &out)
		if out["cleared"] != true {
			t.Fatalf("out = %+v, want cleared:true", out)
		}
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM attackpath_asset_tags WHERE host_key='FILESRV01'`).Scan(&n)
		if n != 0 {
			t.Fatalf("expected tag deleted, found %d rows", n)
		}
	})
}

// TestGetAttackPathAssets_OverlaysStoredTagsAndUntaggedHosts pins that the
// asset inventory (a) reflects the current fleet graph, (b) overlays stored
// tag values onto matching hosts, and (c) still surfaces a tag for a host
// that hasn't been collected yet (operator pre-tags before the agent reports).
func TestGetAttackPathAssets_OverlaysStoredTagsAndUntaggedHosts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		h.SubmitAttackPathCollection(httptest.NewRecorder(), collectionReq(minimalCollection("assets-agent", "COLLECTED-HOST", "agent")))
		h.SetAttackPathAsset(httptest.NewRecorder(), assetTagReq(attackpath.AssetTag{HostKey: "COLLECTED-HOST", CrownJewel: "ERP"}))
		h.SetAttackPathAsset(httptest.NewRecorder(), assetTagReq(attackpath.AssetTag{HostKey: "NOT-YET-COLLECTED", Segment: "dmz"}))

		rec := httptest.NewRecorder()
		h.GetAttackPathAssets(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var out struct {
			Assets []attackpath.AssetTag `json:"assets"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out.Assets) != 2 {
			t.Fatalf("assets = %+v, want 2 (one collected+tagged, one tag-only)", out.Assets)
		}
		byKey := map[string]attackpath.AssetTag{}
		for _, a := range out.Assets {
			byKey[a.HostKey] = a
		}
		if byKey["COLLECTED-HOST"].CrownJewel != "ERP" {
			t.Errorf("COLLECTED-HOST crownJewel = %q, want ERP", byKey["COLLECTED-HOST"].CrownJewel)
		}
		if byKey["NOT-YET-COLLECTED"].Segment != "dmz" {
			t.Errorf("NOT-YET-COLLECTED segment = %q, want dmz", byKey["NOT-YET-COLLECTED"].Segment)
		}
	})
}

func TestGetAttackPathSubnet_MissingAgentID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetAttackPathSubnet(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", ""))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestGetAttackPathSubnet_NoIPRecorded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetAttackPathSubnet(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "no-such-agent"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Subnet  string   `json:"subnet"`
			Targets []string `json:"targets"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Subnet != "" || len(out.Targets) != 0 {
			t.Fatalf("out = %+v, want empty subnet/targets when no IP recorded", out)
		}
	})
}

// TestGetAttackPathSubnet_DerivesFullTargetList pins the /24 derivation: 253
// candidate addresses (254 minus the agent's own IP), correct subnet string.
func TestGetAttackPathSubnet_DerivesFullTargetList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		_, err := pool.Exec(context.Background(),
			`INSERT INTO agents (agent_id, hostname, ip_address) VALUES ($1,$2,$3)`,
			"subnet-agent", "SUBNET-HOST", "10.20.30.42")
		if err != nil {
			t.Fatalf("seed agent: %v", err)
		}

		rec := httptest.NewRecorder()
		h.GetAttackPathSubnet(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "subnet-agent"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			AgentIP string   `json:"agentIp"`
			Subnet  string   `json:"subnet"`
			Targets []string `json:"targets"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Subnet != "10.20.30.0/24" {
			t.Errorf("subnet = %q, want 10.20.30.0/24", out.Subnet)
		}
		if len(out.Targets) != 253 {
			t.Fatalf("targets = %d, want 253 (254 minus the agent's own IP)", len(out.Targets))
		}
		for _, tg := range out.Targets {
			if tg == "10.20.30.42" {
				t.Fatal("target list should exclude the agent's own IP")
			}
		}
	})
}
