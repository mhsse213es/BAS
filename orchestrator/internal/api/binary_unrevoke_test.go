package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/integrity"
	"github.com/audspect/bas/internal/license"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

const (
	unrevHashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	unrevHashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	unrevHashS = "5555555555555555555555555555555555555555555555555555555555555555"
)

// binRouter mounts the real routes with a manifest built from lines.
func binRouter(t *testing.T, pool *pgxpool.Pool, manifestLines ...string) http.Handler {
	t.Helper()
	path := filepath.Join(t.TempDir(), "BINARIES.sha256")
	if err := os.WriteFile(path, []byte(strings.Join(manifestLines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
	h.manifest = integrity.LoadManifest(path)
	prev := license.Current()
	license.SetInitial(license.Info{State: license.StateValid, Tier: license.TierEnterprise})
	t.Cleanup(func() { license.SetInitial(prev) })
	return Mount(h, ws.NewHub(), testJWTSecret, "", http.NotFoundHandler(), 0, 0)
}

func binJWT(t *testing.T, role auth.Role) string {
	t.Helper()
	tenant := "default"
	tok, err := auth.GenerateTenantToken("bin-"+string(role), role, &tenant, false, testJWTSecret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func binDo(router http.Handler, method, path, bearer, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func agentState(t *testing.T, pool *pgxpool.Pool, id string) (string, bool) {
	t.Helper()
	var st string
	var trusted bool
	if err := pool.QueryRow(context.Background(), `SELECT state, binary_trusted FROM agents WHERE agent_id=$1`, id).Scan(&st, &trusted); err != nil {
		t.Fatal(err)
	}
	return st, trusted
}

// A console revocation can be reversed by an admin. Reversing it lifts the revocation but does not return anyone to
// service: agents stay quarantined until an operator restores them, which re-checks trust. Both actions are audited.
func TestUnrevoke_ReversesAConsoleRevocationAndLeavesAgentsQuarantined(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id, hostname, state, binary_hash, binary_trusted) VALUES ('unrev-1','h','active',$1,true)`, unrevHashA); err != nil {
			t.Fatal(err)
		}
		router := binRouter(t, pool, unrevHashS+"  bas-agent-linux-amd64")
		admin, analyst := binJWT(t, auth.RoleAdmin), binJWT(t, auth.RoleAnalyst)

		if rec := binDo(router, http.MethodPost, "/api/agent-binaries/revocations", admin, `{"sha256":"`+unrevHashA+`","reason":"bad build"}`); rec.Code != http.StatusOK {
			t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
		}
		if st, _ := agentState(t, pool, "unrev-1"); st != "quarantined" {
			t.Fatalf("after revoke the agent is %q, want quarantined", st)
		}

		if c := binDo(router, http.MethodDelete, "/api/agent-binaries/revocations/"+unrevHashA, analyst, "").Code; c != http.StatusForbidden {
			t.Errorf("an analyst reversing a revocation: %d, want 403", c)
		}
		rec := binDo(router, http.MethodDelete, "/api/agent-binaries/revocations/"+strings.ToUpper(unrevHashA), admin, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("un-revoke: %d %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Sha256          string `json:"sha256"`
			AgentsStillHeld int    `json:"agentsStillQuarantined"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Sha256 != unrevHashA || out.AgentsStillHeld != 1 {
			t.Errorf("response = %+v, want the hash and 1 agent still quarantined", out)
		}
		if st, trusted := agentState(t, pool, "unrev-1"); st != "quarantined" || trusted {
			t.Errorf("after un-revoke the agent is %q trusted=%v: it must stay quarantined until restored", st, trusted)
		}

		var left int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM binary_revocations WHERE sha256=$1`, unrevHashA).Scan(&left)
		if left != 0 {
			t.Errorf("revocation rows left = %d, want 0", left)
		}
		for _, action := range []string{"agent_binary.revoke", "agent_binary.unrevoke"} {
			var n int
			for i := 0; i < 50 && n == 0; i++ {
				_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action=$1 AND resource=$2`, action, unrevHashA).Scan(&n)
				if n == 0 {
					time.Sleep(100 * time.Millisecond)
				}
			}
			if n != 1 {
				t.Errorf("audit rows for %s = %d, want 1", action, n)
			}
		}
	})
}

// A revocation written into the signed release cannot be reversed from the console, and the list says so.
func TestUnrevoke_SignedRevocationCannotBeReversedAndIsListedAsSuch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := binRouter(t, pool, unrevHashS+"  bas-agent-linux-amd64", "#revoked "+unrevHashB+"  bas-agent-darwin-arm64")
		admin := binJWT(t, auth.RoleAdmin)

		rec := binDo(router, http.MethodDelete, "/api/agent-binaries/revocations/"+unrevHashB, admin, "")
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "signed release") {
			t.Fatalf("reversing a signed revocation: %d %s, want 409 naming the signed release", rec.Code, rec.Body.String())
		}

		rec = binDo(router, http.MethodGet, "/api/agent-binaries/revocations", admin, "")
		var list struct {
			Items []struct {
				SHA256     string `json:"sha256"`
				Source     string `json:"source"`
				Reversible bool   `json:"reversible"`
			} `json:"items"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, it := range list.Items {
			if it.SHA256 == unrevHashB {
				found = true
				if it.Source != "release" || it.Reversible {
					t.Errorf("signed revocation listed as source=%q reversible=%v, want release / false", it.Source, it.Reversible)
				}
			}
		}
		if !found {
			t.Errorf("the signed revocation is not in the list: %s", rec.Body.String())
		}
	})
}

func TestUnrevoke_Validation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := binRouter(t, pool, unrevHashS+"  bas-agent-linux-amd64")
		admin := binJWT(t, auth.RoleAdmin)
		if c := binDo(router, http.MethodDelete, "/api/agent-binaries/revocations/not-a-hash", admin, "").Code; c != http.StatusBadRequest {
			t.Errorf("bad hash: %d, want 400", c)
		}
		if c := binDo(router, http.MethodDelete, "/api/agent-binaries/revocations/"+unrevHashB, admin, "").Code; c != http.StatusNotFound {
			t.Errorf("a hash that is not revoked: %d, want 404", c)
		}
	})
}

type minVersionResp struct {
	Version string `json:"version"`
	Source  string `json:"source"`
	Default string `json:"default"`
}

func getMinVersion(t *testing.T, router http.Handler, admin string) minVersionResp {
	t.Helper()
	rec := binDo(router, http.MethodGet, "/api/fleet/min-agent-version", admin, "")
	var r minVersionResp
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("min version response: %v %s", err, rec.Body.String())
	}
	return r
}

// With no stored setting the minimum is the previous release. An administrator's setting, including "none", wins, and
// removing it brings the default back.
func TestMinAgentVersion_DefaultsToThePreviousRelease(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		router := binRouter(t, pool, unrevHashS+"  bas-agent-linux-amd64", "#prev-version 1.9.9.3")
		admin := binJWT(t, auth.RoleAdmin)
		_, _ = pool.Exec(ctx, `DELETE FROM fleet_settings WHERE key='min_agent_version'`)

		if r := getMinVersion(t, router, admin); r.Version != "1.9.9.3" || r.Source != "previous-release" || r.Default != "1.9.9.3" {
			t.Fatalf("no setting: %+v, want 1.9.9.3 from the previous release", r)
		}

		// An agent below the default is flagged; one at or above is not.
		for id, ver := range map[string]string{"mv-old": "1.9.8", "mv-ok": "1.9.9.3"} {
			if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id, hostname, agent_version) VALUES ($1,'h',$2) ON CONFLICT (agent_id) DO UPDATE SET agent_version=$2`, id, ver); err != nil {
				t.Fatal(err)
			}
		}
		rec := binDo(router, http.MethodGet, "/api/agents", admin, "")
		below := map[string]bool{}
		var agents []struct {
			AgentID         string `json:"agentId"`
			BelowMinVersion bool   `json:"belowMinVersion"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &agents); err != nil {
			var wrapped struct {
				Agents []struct {
					AgentID         string `json:"agentId"`
					BelowMinVersion bool   `json:"belowMinVersion"`
				} `json:"agents"`
			}
			if err2 := json.Unmarshal(rec.Body.Bytes(), &wrapped); err2 != nil {
				t.Fatalf("agents response: %v %s", err, rec.Body.String())
			}
			agents = wrapped.Agents
		}
		for _, a := range agents {
			below[a.AgentID] = a.BelowMinVersion
		}
		if !below["mv-old"] || below["mv-ok"] {
			t.Errorf("below-minimum flags = %v, want mv-old true and mv-ok false", below)
		}

		if c := binDo(router, http.MethodPut, "/api/fleet/min-agent-version", admin, `{"version":""}`).Code; c != http.StatusOK {
			t.Fatalf("clearing: %d", c)
		}
		if r := getMinVersion(t, router, admin); r.Version != "" || r.Source != "setting" || r.Default != "1.9.9.3" {
			t.Errorf("explicitly cleared: %+v, want none from the setting (the default stays visible)", r)
		}
		if c := binDo(router, http.MethodPut, "/api/fleet/min-agent-version", admin, `{"version":"1.9.0"}`).Code; c != http.StatusOK {
			t.Fatal("setting failed")
		}
		if r := getMinVersion(t, router, admin); r.Version != "1.9.0" || r.Source != "setting" {
			t.Errorf("set: %+v", r)
		}
		if c := binDo(router, http.MethodDelete, "/api/fleet/min-agent-version", admin, "").Code; c != http.StatusOK {
			t.Fatalf("resetting: %d", c)
		}
		if r := getMinVersion(t, router, admin); r.Version != "1.9.9.3" || r.Source != "previous-release" {
			t.Errorf("after reset: %+v, want the default back", r)
		}
	})
}

func TestMinAgentVersion_NoPreviousVersionInTheManifestMeansNoMinimum(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := binRouter(t, pool, unrevHashS+"  bas-agent-linux-amd64")
		admin := binJWT(t, auth.RoleAdmin)
		_, _ = pool.Exec(context.Background(), `DELETE FROM fleet_settings WHERE key='min_agent_version'`)
		if r := getMinVersion(t, router, admin); r.Version != "" || r.Source != "none" {
			t.Errorf("%+v, want no minimum when the release does not name its predecessor", r)
		}
	})
}
