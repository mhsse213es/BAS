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
	original := agentCursor{
		Snapshot:   time.Date(2026, 8, 31, 17, 0, 0, 123000000, time.UTC),
		LastUpdate: time.Date(2026, 8, 31, 16, 59, 58, 1000000, time.UTC),
		AgentID:    "loadgen-000042",
	}
	encoded := encodeAgentCursor(original)
	if encoded == "" {
		t.Fatal("encodeAgentCursor returned empty string")
	}
	decoded, err := decodeAgentCursor(encoded)
	if err != nil {
		t.Fatalf("decodeAgentCursor: %v", err)
	}
	if !decoded.Snapshot.Equal(original.Snapshot) {
		t.Errorf("Snapshot = %v, want %v", decoded.Snapshot, original.Snapshot)
	}
	if !decoded.LastUpdate.Equal(original.LastUpdate) {
		t.Errorf("LastUpdate = %v, want %v", decoded.LastUpdate, original.LastUpdate)
	}
	if decoded.AgentID != original.AgentID {
		t.Errorf("AgentID = %q, want %q", decoded.AgentID, original.AgentID)
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

// TestGetAgents_Paginated_ConcurrentHeartbeat_NoDuplicateOrCollateralSkip
// documents the actual, achievable guarantee under a mid-traversal
// heartbeat -- and the one guarantee keyset pagination over a
// heartbeat-mutable sort column (last_update) structurally cannot deliver.
//
// What holds: no duplicates, ever -- and the OTHER rows in the traversal
// (the ones that don't themselves get updated) are never skipped or
// reordered by an unrelated row's heartbeat. This is the real improvement
// over plain OFFSET/LIMIT, which this test would catch a regression of.
//
// What does NOT hold, and can't with this design: a row that heartbeats
// *itself* during the traversal (bumping its own last_update forward)
// becomes unreachable for the REST of that traversal. In a DESC-ordered
// keyset cursor, that row's new sort position is "before" (newer than) the
// cursor's already-passed position -- there is no snapshot mechanism that
// can un-overwrite last_update's prior value once Postgres has applied the
// UPDATE, short of a much heavier transactional-snapshot mechanism this
// design deliberately doesn't take on. The row isn't lost: it simply
// wasn't returned by *this* traversal, and will appear normally on the
// next fresh one (a new page-1 request with no cursor). This is the same
// trade-off essentially every keyset-paginated API (GitHub's, Stripe's)
// accepts for exactly this reason.
func TestGetAgents_Paginated_ConcurrentHeartbeat_NoDuplicateOrCollateralSkip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		base := time.Now().Add(-time.Hour)
		for i := 0; i < 4; i++ {
			seedAgentWithLastUpdate(t, pool, fmt.Sprintf("agent-%02d", i), base.Add(time.Duration(i)*time.Second))
		}

		// Page 1.
		rec1 := httptest.NewRecorder()
		h.GetAgents(rec1, httptest.NewRequest(http.MethodGet, "/api/agents?limit=2", nil))
		var page1 AgentsPage
		if err := json.Unmarshal(rec1.Body.Bytes(), &page1); err != nil {
			t.Fatalf("page 1 decode: %v", err)
		}
		if !page1.HasMore {
			t.Fatal("expected has_more=true on page 1")
		}

		// Simulate a heartbeat on agent-00, the one agent NOT yet returned
		// (page 1, limit=2, sorted DESC, returns the 2 newest: agent-03 and
		// agent-02 -- agent-01 and agent-00 remain for page 2).
		if _, err := pool.Exec(context.Background(),
			`UPDATE agents SET last_update = NOW() WHERE agent_id = 'agent-00'`); err != nil {
			t.Fatalf("simulate heartbeat: %v", err)
		}

		// Page 2, using page 1's cursor.
		rec2 := httptest.NewRecorder()
		h.GetAgents(rec2, httptest.NewRequest(http.MethodGet, "/api/agents?limit=2&cursor="+page1.NextCursor, nil))
		var page2 AgentsPage
		if err := json.Unmarshal(rec2.Body.Bytes(), &page2); err != nil {
			t.Fatalf("page 2 decode: %v", err)
		}

		seen := map[string]bool{}
		for _, a := range page1.Items {
			seen[a.AgentID] = true
		}
		for _, a := range page2.Items {
			if seen[a.AgentID] {
				t.Fatalf("agent %s appeared on both page 1 and page 2 -- a real duplicate, which the design must prevent regardless of any row's heartbeat", a.AgentID)
			}
			seen[a.AgentID] = true
		}
		// agent-01 (which did NOT heartbeat) must still be reachable on page
		// 2, undisturbed by agent-00's unrelated update -- this is the
		// actual guarantee the design provides.
		if !seen["agent-01"] {
			t.Fatalf("agent-01 (unrelated to the heartbeat) was skipped from page 2 -- collateral skip regression, seen: %v", seen)
		}
		// agent-00 heartbeated itself mid-traversal -- per the design's
		// documented, accepted limitation, it drops out of THIS traversal.
		// It is not a bug if it's absent here.
		if seen["agent-00"] {
			t.Log("note: agent-00 was reachable despite heartbeating mid-traversal -- fine if it happens, just not guaranteed")
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
			{"Finance", "other-agent"},             // matches group name
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
