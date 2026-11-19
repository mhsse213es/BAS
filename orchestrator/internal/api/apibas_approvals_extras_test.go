package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/notifications"
)

// captureBroadcaster records the live messages the notification service pushes to browsers.
type captureBroadcaster struct {
	mu   sync.Mutex
	msgs []models.WSMessage
}

func (c *captureBroadcaster) BroadcastBrowsers(m models.WSMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, m)
}

func (c *captureBroadcaster) events() []notifications.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []notifications.Event
	for _, m := range c.msgs {
		if e, ok := m.Data.(notifications.Event); ok {
			out = append(out, e)
		}
	}
	return out
}

func TestAPIBASApprovalListPagesAndFiltersByRequester(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	if rec := postAs(t, h, "/api/apibas/targets", targetBody("page-prod", "production"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	req := map[string]any{"target_id": "page-prod", "fixture": "orders-two-tenant", "scenario_ids": []string{"API-BAS-AUTHZ-001"}}
	want := map[string]string{} // id -> requester
	for i := 0; i < 5; i++ {
		user := "pager-a"
		if i%2 == 1 {
			user = "pager-b"
		}
		rec := postAs(t, h, "/api/apibas/approvals", req, auth.RoleAnalyst, user)
		var c struct{ ID string }
		_ = json.Unmarshal(rec.Body.Bytes(), &c)
		if c.ID == "" {
			t.Fatalf("request %d: %d %s", i, rec.Code, rec.Body.String())
		}
		want[c.ID] = user
	}
	type page struct {
		Approvals  []map[string]any `json:"approvals"`
		NextCursor string           `json:"next_cursor"`
	}
	get := func(query string) (int, page) {
		rec := getAsUser(t, h, "/api/apibas/approvals"+query, auth.RoleAnalyst, "analyst1")
		var p page
		_ = json.Unmarshal(rec.Body.Bytes(), &p)
		return rec.Code, p
	}
	// Walk the whole list two at a time: every approval appears exactly once, newest first, and the last page has no cursor.
	seen := map[string]bool{}
	var lastCreated string
	cursor, pages := "", 0
	for {
		q := "?state=all&target_id=page-prod&limit=2"
		if cursor != "" {
			q += "&cursor=" + cursor
		}
		code, p := get(q)
		if code != http.StatusOK {
			t.Fatalf("page %d: %d", pages, code)
		}
		pages++
		if len(p.Approvals) > 2 {
			t.Fatalf("page %d has %d rows, limit is 2", pages, len(p.Approvals))
		}
		for _, a := range p.Approvals {
			id, _ := a["id"].(string)
			if seen[id] {
				t.Errorf("approval %s returned twice", id)
			}
			seen[id] = true
			created, _ := a["created_at"].(string)
			if lastCreated != "" && created > lastCreated {
				t.Errorf("order broke at %s: %s after %s", id, created, lastCreated)
			}
			lastCreated = created
		}
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
		if pages > 10 {
			t.Fatal("paging did not end")
		}
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("approval %s never appeared while paging", id)
		}
	}
	if pages != 3 {
		t.Errorf("5 rows at 2 per page took %d pages, want 3", pages)
	}
	// Requester filter.
	_, p := get("?state=all&target_id=page-prod&requested_by=pager-b")
	if len(p.Approvals) != 2 {
		t.Errorf("pager-b has %d approvals, want 2", len(p.Approvals))
	}
	for _, a := range p.Approvals {
		if a["requested_by"] != "pager-b" {
			t.Errorf("filter returned %v", a["requested_by"])
		}
	}
	if code, _ := get("?cursor=not-a-cursor"); code != http.StatusBadRequest {
		t.Errorf("bad cursor: %d, want 400", code)
	}
}

func TestAPIBASApprovalEventsAreNotified(t *testing.T) {
	hh := jobsHandler(t, true)
	bc := &captureBroadcaster{}
	hh.notifications = notifications.NewService(notifications.NewStore(sharedDB.Pool), bc)
	h := jobsRouter(hh)
	if rec := postAs(t, h, "/api/apibas/targets", targetBody("notify-prod", "production"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	req := map[string]any{"target_id": "notify-prod", "fixture": "orders-two-tenant", "scenario_ids": []string{"API-BAS-AUTHZ-001"}}
	rec := postAs(t, h, "/api/apibas/approvals", req, auth.RoleAnalyst, "analyst1")
	var c struct{ ID string }
	_ = json.Unmarshal(rec.Body.Bytes(), &c)
	if rec := postAs(t, h, "/api/apibas/approvals/"+c.ID+"/approve", map[string]any{}, auth.RoleAdmin, "admin2"); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d", rec.Code)
	}
	if rec := postAs(t, h, "/api/apibas/approvals/"+c.ID+"/revoke", map[string]any{"reason": "r"}, auth.RoleAdmin, "admin3"); rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d", rec.Code)
	}
	got := map[notifications.EventType]notifications.Event{}
	for _, e := range bc.events() {
		if e.TargetID == "notify-prod" {
			got[e.Type] = e
		}
	}
	for _, typ := range []notifications.EventType{notifications.EventAPIBASApprovalRequested, notifications.EventAPIBASApprovalApproved, notifications.EventAPIBASApprovalRevoked} {
		e, ok := got[typ]
		if !ok {
			t.Errorf("no %s notification was pushed", typ)
			continue
		}
		if e.Metadata["approval_id"] != c.ID {
			t.Errorf("%s metadata = %v, want approval_id %s", typ, e.Metadata, c.ID)
		}
		for k, v := range e.Metadata {
			if s, _ := v.(string); k == "binding_hash" || strings.Contains(strings.ToLower(k), "hash") || len(s) == 64 {
				t.Errorf("%s carries %s=%v; the binding hash must not be published", typ, k, v)
			}
		}
	}
	if got[notifications.EventAPIBASApprovalRequested].Severity != notifications.SeverityWarning {
		t.Error("the request notification should be a warning so severity-filtered webhooks receive it")
	}
	// Persisted, not just pushed.
	deadline := time.Now().Add(2 * time.Second)
	var stored int
	for time.Now().Before(deadline) {
		_ = sharedDB.Pool.QueryRow(context.Background(),
			`SELECT count(*) FROM notifications WHERE target_id = 'notify-prod' AND type LIKE 'apibas_approval_%'`).Scan(&stored)
		if stored == 3 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if stored != 3 {
		t.Errorf("%d approval notifications stored, want 3", stored)
	}
	// Without the notification service the endpoints still work.
	plain := jobsRouter(jobsHandler(t, true))
	if rec := postAs(t, plain, "/api/apibas/approvals", req, auth.RoleAnalyst, "analyst1"); rec.Code != http.StatusCreated {
		t.Errorf("no notification service: %d, want 201", rec.Code)
	}
}
