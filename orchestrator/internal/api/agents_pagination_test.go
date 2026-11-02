package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAgentCursor_EncodeDecodeRoundTrip(t *testing.T) {
	original := agentCursor{Hostname: "loadgen-host", AgentID: "loadgen-000042", Alpha: true}
	encoded := encodeAgentCursor(original)
	if encoded == "" {
		t.Fatal("encodeAgentCursor returned empty string")
	}
	decoded, err := decodeAgentCursor(encoded)
	if err != nil {
		t.Fatalf("decodeAgentCursor: %v", err)
	}
	if decoded != original {
		t.Errorf("decoded = %+v, want %+v", decoded, original)
	}
}

func TestDecodeAgentCursor_RejectsGarbage(t *testing.T) {
	if _, err := decodeAgentCursor("not-valid-base64!!!"); err == nil {
		t.Fatal("expected an error decoding garbage input, got nil")
	}
	// Valid base64, but not valid JSON underneath.
	if _, err := decodeAgentCursor("bm90LWpzb24="); err == nil {
		t.Fatal("expected an error decoding valid-base64-but-not-JSON input, got nil")
	}
}

func seedAgentWithLastUpdate(t *testing.T, pool *pgxpool.Pool, agentID string, lastUpdate time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agents (agent_id, hostname, last_update) VALUES ($1, $2, $3)`,
		agentID, "h-"+agentID, lastUpdate); err != nil {
		t.Fatalf("seed agent %s: %v", agentID, err)
	}
}

func TestGetAgents_Unpaginated_StillReturnsBareArray(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		seedActiveAgent(t, pool, "agent-plain", "Windows")

		rec := httptest.NewRecorder()
		h.GetAgents(rec, httptest.NewRequest(http.MethodGet, "/api/agents", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		// Must decode as a bare array -- decoding into a map/object would fail
		// if the handler ever started returning the paginated envelope here.
		var agents []models.Agent
		if err := json.Unmarshal(rec.Body.Bytes(), &agents); err != nil {
			t.Fatalf("response is not a bare array (pagination leaked into the no-params path?): %v", err)
		}
		if len(agents) != 1 || agents[0].AgentID != "agent-plain" {
			t.Fatalf("got %+v, want exactly [agent-plain]", agents)
		}
	})
}

func TestGetAgents_Paginated_TraversesAllPagesWithoutSkipOrDuplicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		base := time.Now().Add(-time.Hour)
		for i := 0; i < 5; i++ {
			seedAgentWithLastUpdate(t, pool, fmt.Sprintf("agent-%02d", i), base.Add(time.Duration(i)*time.Second))
		}

		seen := map[string]bool{}
		cursor := ""
		pages := 0
		for {
			url := "/api/agents?limit=2"
			if cursor != "" {
				url += "&cursor=" + cursor
			}
			rec := httptest.NewRecorder()
			h.GetAgents(rec, httptest.NewRequest(http.MethodGet, url, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("page %d: status = %d, body = %s", pages, rec.Code, rec.Body.String())
			}
			var page AgentsPage
			if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
				t.Fatalf("page %d: decode: %v", pages, err)
			}
			for _, a := range page.Items {
				if seen[a.AgentID] {
					t.Fatalf("agent %s returned on more than one page", a.AgentID)
				}
				seen[a.AgentID] = true
			}
			pages++
			if !page.HasMore {
				break
			}
			if page.NextCursor == "" {
				t.Fatal("has_more=true but next_cursor is empty")
			}
			cursor = page.NextCursor
			if pages > 10 {
				t.Fatal("pagination did not terminate after 10 pages")
			}
		}
		if len(seen) != 5 {
			t.Fatalf("saw %d distinct agents across all pages, want 5: %v", len(seen), seen)
		}
		if pages != 3 { // 2 + 2 + 1
			t.Fatalf("took %d pages to see all 5 agents at limit=2, want 3", pages)
		}
	})
}

// TestGetAgents_Paginated_ConcurrentHeartbeat_NoDuplicateOrSkip: the list is ordered by hostname, which a
// heartbeat never changes, so an agent heartbeating mid-traversal -- before OR after its page -- is neither
// duplicated nor skipped. (Ordered by last_update, as it used to be, a row that heartbeated itself jumped
// ahead of the cursor and dropped out of the traversal.)
func TestGetAgents_Paginated_ConcurrentHeartbeat_NoDuplicateOrSkip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		base := time.Now().Add(-time.Hour)
		for i := 0; i < 4; i++ {
			seedAgentWithLastUpdate(t, pool, fmt.Sprintf("agent-%02d", i), base.Add(time.Duration(i)*time.Second))
		}

		rec1 := httptest.NewRecorder()
		h.GetAgents(rec1, httptest.NewRequest(http.MethodGet, "/api/agents?limit=2", nil))
		var page1 AgentsPage
		if err := json.Unmarshal(rec1.Body.Bytes(), &page1); err != nil {
			t.Fatalf("page 1 decode: %v", err)
		}
		if !page1.HasMore {
			t.Fatal("expected has_more=true on page 1")
		}

		// agent-00 (already returned) and agent-03 (not yet returned) both heartbeat mid-traversal.
		for _, id := range []string{"agent-00", "agent-03"} {
			if _, err := pool.Exec(context.Background(), `UPDATE agents SET last_update = NOW() WHERE agent_id = $1`, id); err != nil {
				t.Fatalf("simulate heartbeat: %v", err)
			}
		}

		rec2 := httptest.NewRecorder()
		h.GetAgents(rec2, httptest.NewRequest(http.MethodGet, "/api/agents?limit=2&cursor="+page1.NextCursor, nil))
		var page2 AgentsPage
		if err := json.Unmarshal(rec2.Body.Bytes(), &page2); err != nil {
			t.Fatalf("page 2 decode: %v", err)
		}

		var order []string
		for _, a := range append(append([]models.Agent{}, page1.Items...), page2.Items...) {
			order = append(order, a.AgentID)
		}
		want := []string{"agent-00", "agent-01", "agent-02", "agent-03"}
		if fmt.Sprint(order) != fmt.Sprint(want) {
			t.Fatalf("traversal = %v, want %v (every agent exactly once, in hostname order)", order, want)
		}
	})
}

// The list order is hostname A-Z, case-insensitive, and does not move when an agent heartbeats.
func TestGetAgents_OrderedByHostnameAndStableAcrossHeartbeats(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		now := time.Now()
		for i, host := range []string{"zulu", "Alpha", "mike", "bravo"} {
			if _, err := pool.Exec(context.Background(),
				`INSERT INTO agents (agent_id, hostname, last_update) VALUES ($1, $2, $3)`,
				fmt.Sprintf("id-%d", i), host, now.Add(-time.Duration(i)*time.Minute)); err != nil {
				t.Fatalf("seed: %v", err)
			}
		}
		list := func() string {
			rec := httptest.NewRecorder()
			h.GetAgents(rec, httptest.NewRequest(http.MethodGet, "/api/agents?limit=50", nil))
			var page AgentsPage
			if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
				t.Fatalf("decode: %v (%s)", err, rec.Body.String())
			}
			var hosts []string
			for _, a := range page.Items {
				hosts = append(hosts, a.Hostname)
			}
			return fmt.Sprint(hosts)
		}
		want := "[Alpha bravo mike zulu]"
		if got := list(); got != want {
			t.Fatalf("order = %s, want %s", got, want)
		}
		// zulu was the OLDEST heartbeat; making it the newest must not move it.
		if _, err := pool.Exec(context.Background(), `UPDATE agents SET last_update = NOW() + interval '1 minute' WHERE hostname = 'zulu'`); err != nil {
			t.Fatalf("heartbeat: %v", err)
		}
		if got := list(); got != want {
			t.Fatalf("order after a heartbeat = %s, want %s unchanged", got, want)
		}
	})
}

func TestGetAgents_Paginated_TotalsMatchSeededBuckets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		now := time.Now()
		seedAgentWithLastUpdate(t, pool, "agent-online", now)
		seedAgentWithLastUpdate(t, pool, "agent-offline", now.Add(-5*time.Minute)) // >90s stale
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO agents (agent_id, hostname, last_update, state) VALUES ('agent-degraded','h', $1, 'quarantined')`, now); err != nil {
			t.Fatalf("seed degraded: %v", err)
		}
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO agents (agent_id, hostname, last_update, state) VALUES ('agent-retired','h', $1, 'retired')`, now); err != nil {
			t.Fatalf("seed retired: %v", err)
		}

		rec := httptest.NewRecorder()
		h.GetAgents(rec, httptest.NewRequest(http.MethodGet, "/api/agents?limit=100", nil))
		var page AgentsPage
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatalf("decode: %v", err)
		}
		want := AgentTotals{Online: 1, Degraded: 1, Offline: 1, Retired: 1}
		if page.Totals != want {
			t.Errorf("Totals = %+v, want %+v", page.Totals, want)
		}
	})
}

func TestGetAgents_Paginated_BucketFilterScopesRowList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		now := time.Now()
		seedAgentWithLastUpdate(t, pool, "agent-online", now)
		seedAgentWithLastUpdate(t, pool, "agent-offline", now.Add(-5*time.Minute))

		rec := httptest.NewRecorder()
		h.GetAgents(rec, httptest.NewRequest(http.MethodGet, "/api/agents?limit=100&bucket=offline", nil))
		var page AgentsPage
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(page.Items) != 1 || page.Items[0].AgentID != "agent-offline" {
			t.Fatalf("got %+v, want exactly [agent-offline]", page.Items)
		}
	})
}

func TestGetAgents_Paginated_SearchMatchesHostnameAgentIDAndGroupName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		seedActiveAgent(t, pool, "special-agent-id", "Windows")
		seedActiveAgent(t, pool, "other-agent", "Linux")
		seedAgentGroup(t, pool, "Finance-Group", "other-agent")

		cases := []struct {
			q    string
			want string
		}{
			{"special-agent", "special-agent-id"}, // matches agent_id
			{"Finance", "other-agent"},            // matches group name
		}
		for _, c := range cases {
			rec := httptest.NewRecorder()
			h.GetAgents(rec, httptest.NewRequest(http.MethodGet, "/api/agents?limit=100&q="+c.q, nil))
			var page AgentsPage
			if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
				t.Fatalf("q=%s: decode: %v", c.q, err)
			}
			if len(page.Items) != 1 || page.Items[0].AgentID != c.want {
				t.Errorf("q=%s: got %+v, want exactly [%s]", c.q, page.Items, c.want)
			}
		}
	})
}

func TestGetAgents_InvalidCursor_Returns400(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		rec := httptest.NewRecorder()
		h.GetAgents(rec, httptest.NewRequest(http.MethodGet, "/api/agents?cursor=not-a-valid-cursor!!!", nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}
	})
}
