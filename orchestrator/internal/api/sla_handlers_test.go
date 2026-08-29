package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/notifications"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func seedFindingSLA(t *testing.T, pool *pgxpool.Pool, id, agentID, checkID, severity, status string, deadlineAt time.Time, breachedAt *time.Time) {
	t.Helper()
	pfID := "pf-" + id
	mustExecAPI(t, pool,
		`INSERT INTO posture_findings (id, agent_id, check_id, category, title, severity, status, first_seen, last_seen, last_observed_at)
		 VALUES ($1,$2,$3,'security-configuration','Test Finding',$4,'open',NOW(),NOW(),NOW())
		 ON CONFLICT (agent_id, check_id) DO NOTHING`,
		pfID, agentID, checkID, severity)
	mustExecAPI(t, pool,
		`INSERT INTO finding_slas (id, posture_finding_id, severity_at_start, started_at, deadline_at, status, breached_at)
		 VALUES ($1, $2, $3, NOW(), $4, $5, $6)`,
		id, pfID, severity, deadlineAt, status, breachedAt)
}

func TestTickSLABreaches_DeadlineNotReached_NoBreach(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tick-a1', 'TICK-A1')`)
		seedFindingSLA(t, pool, "fs-notdue", "tick-a1", "windows-firewall-enabled", "High", "active", time.Now().Add(time.Hour), nil)

		notifStore := notifications.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithNotifications(notifStore)
		if err := h.TickSLABreaches(context.Background()); err != nil {
			t.Fatalf("TickSLABreaches: %v", err)
		}

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM finding_slas WHERE id='fs-notdue'`).Scan(&status)
		if status != "active" {
			t.Errorf("status = %q, want still active", status)
		}
	})
}

func TestTickSLABreaches_DeadlinePassed_MarksBreachedAndNotifies(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tick-a2', 'TICK-A2')`)
		seedFindingSLA(t, pool, "fs-due", "tick-a2", "linux-ssh-empty-passwords-forbidden", "Critical", "active", time.Now().Add(-time.Hour), nil)

		notifStore := notifications.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithNotifications(notifStore)
		if err := h.TickSLABreaches(context.Background()); err != nil {
			t.Fatalf("TickSLABreaches: %v", err)
		}

		var status string
		var breachedAt *time.Time
		pool.QueryRow(context.Background(), `SELECT status, breached_at FROM finding_slas WHERE id='fs-due'`).Scan(&status, &breachedAt)
		if status != "breached" || breachedAt == nil {
			t.Fatalf("status=%q breachedAt=%v, want breached/non-nil", status, breachedAt)
		}

		events, err := notifStore.List(context.Background(), notifications.ListFilter{Type: string(notifications.EventSLABreached), Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(events) != 1 || events[0].Severity != notifications.SeverityCritical || events[0].AgentID != "tick-a2" {
			t.Fatalf("events = %+v, want exactly one sla_breached/critical event for tick-a2", events)
		}
	})
}

func TestTickSLABreaches_RepeatedTicks_OnlyOneNotification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tick-a3', 'TICK-A3')`)
		seedFindingSLA(t, pool, "fs-repeat", "tick-a3", "windows-firewall-enabled", "High", "active", time.Now().Add(-time.Hour), nil)

		notifStore := notifications.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithNotifications(notifStore)
		h.TickSLABreaches(context.Background())
		h.TickSLABreaches(context.Background())
		h.TickSLABreaches(context.Background())

		events, err := notifStore.List(context.Background(), notifications.ListFilter{Type: string(notifications.EventSLABreached), Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("events = %d, want exactly 1 despite 3 ticks (idempotency)", len(events))
		}
	})
}

func TestTickSLABreaches_MultipleFindingsBreachInSameTick(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tick-a4', 'TICK-A4')`)
		seedFindingSLA(t, pool, "fs-multi1", "tick-a4", "windows-firewall-enabled", "High", "active", time.Now().Add(-time.Hour), nil)
		seedFindingSLA(t, pool, "fs-multi2", "tick-a4", "windows-smbv1-disabled", "High", "active", time.Now().Add(-2*time.Hour), nil)

		notifStore := notifications.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithNotifications(notifStore)
		if err := h.TickSLABreaches(context.Background()); err != nil {
			t.Fatalf("TickSLABreaches: %v", err)
		}

		var breachedCount int
		pool.QueryRow(context.Background(), `SELECT count(*) FROM finding_slas WHERE status='breached'`).Scan(&breachedCount)
		if breachedCount != 2 {
			t.Errorf("breached count = %d, want 2", breachedCount)
		}
		events, _ := notifStore.List(context.Background(), notifications.ListFilter{Type: string(notifications.EventSLABreached), Limit: 10})
		if len(events) != 2 {
			t.Errorf("events = %d, want 2", len(events))
		}
	})
}

func TestTickSLABreaches_ResolvedRowNeverTouched(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tick-a5', 'TICK-A5')`)
		seedFindingSLA(t, pool, "fs-resolved", "tick-a5", "windows-firewall-enabled", "High", "resolved", time.Now().Add(-time.Hour), nil)

		notifStore := notifications.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithNotifications(notifStore)
		if err := h.TickSLABreaches(context.Background()); err != nil {
			t.Fatalf("TickSLABreaches: %v", err)
		}

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM finding_slas WHERE id='fs-resolved'`).Scan(&status)
		if status != "resolved" {
			t.Errorf("status = %q, want still resolved (tick must never touch a non-active row)", status)
		}
		events, _ := notifStore.List(context.Background(), notifications.ListFilter{Type: string(notifications.EventSLABreached), Limit: 10})
		if len(events) != 0 {
			t.Errorf("events = %d, want 0", len(events))
		}
	})
}

func TestListSLAPolicies_ReturnsAllFour(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/sla/policies", nil)
		w := httptest.NewRecorder()
		h.ListSLAPolicies(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var got []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got) != 4 {
			t.Fatalf("len = %d, want 4", len(got))
		}
	})
}

func TestUpdateSLAPolicy_HappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		body, _ := json.Marshal(map[string]int{"durationHours": 8})
		req := withURLParam(httptest.NewRequest(http.MethodPatch, "/x", bytes.NewReader(body)), "severity", "Critical")
		w := httptest.NewRecorder()
		h.UpdateSLAPolicy(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var got int
		pool.QueryRow(context.Background(), `SELECT duration_hours FROM sla_policy WHERE severity='Critical'`).Scan(&got)
		if got != 8 {
			t.Errorf("duration_hours = %d, want 8", got)
		}
	})
}

func TestUpdateSLAPolicy_UnknownSeverity_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		body, _ := json.Marshal(map[string]int{"durationHours": 8})
		req := withURLParam(httptest.NewRequest(http.MethodPatch, "/x", bytes.NewReader(body)), "severity", "Nope")
		w := httptest.NewRecorder()
		h.UpdateSLAPolicy(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}

func TestUpdateSLAPolicy_InvalidDuration_400(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		for _, hours := range []int{0, -5, 9000} {
			body, _ := json.Marshal(map[string]int{"durationHours": hours})
			req := withURLParam(httptest.NewRequest(http.MethodPatch, "/x", bytes.NewReader(body)), "severity", "High")
			w := httptest.NewRecorder()
			h.UpdateSLAPolicy(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("durationHours=%d: status = %d, want 400", hours, w.Code)
			}
		}
	})
}

func TestGetSLABreaches_ReturnsOnlyBreachedOldestFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('breach-a1', 'BREACH-A1')`)
		oldBreach := time.Now().Add(-48 * time.Hour)
		newBreach := time.Now().Add(-12 * time.Hour)
		seedFindingSLA(t, pool, "fs-active", "breach-a1", "windows-firewall-enabled", "High", "active", time.Now().Add(time.Hour), nil)
		seedFindingSLA(t, pool, "fs-b-old", "breach-a1", "windows-smbv1-disabled", "High", "breached", time.Now().Add(-72*time.Hour), &oldBreach)
		seedFindingSLA(t, pool, "fs-b-new", "breach-a1", "windows-rdp-nla-required", "High", "breached", time.Now().Add(-24*time.Hour), &newBreach)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/sla/breaches", nil)
		w := httptest.NewRecorder()
		h.GetSLABreaches(w, req)

		var got []map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		if len(got) != 2 {
			t.Fatalf("len = %d, want 2 (active row excluded)", len(got))
		}
		if got[0]["checkId"] != "windows-smbv1-disabled" {
			t.Errorf("got[0].checkId = %v, want windows-smbv1-disabled (oldest breach first)", got[0]["checkId"])
		}
	})
}

func TestGetSLABreaches_IncludesLatestRemediation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('breach-rt1', 'BREACH-RT1')`)
		breachedAt := time.Now().Add(-1 * time.Hour)
		seedFindingSLA(t, pool, "fs-breach-rt", "breach-rt1", "windows-firewall-enabled", "High", "breached", time.Now().Add(-2*time.Hour), &breachedAt)
		mustExecAPI(t, pool,
			`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, requested_at)
			 VALUES ('rr-breach-rt', 'test-remediation', 'breach-rt1', 'windows-firewall-enabled', 1, 'failed', 'user-1', 'test', $1)`,
			time.Now().Add(time.Minute))

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/sla/breaches", nil)
		w := httptest.NewRecorder()
		h.GetSLABreaches(w, req)

		var got []map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1", len(got))
		}
		lr, ok := got[0]["latestRemediation"].(map[string]any)
		if !ok {
			t.Fatalf("latestRemediation missing or wrong shape: %v", got[0]["latestRemediation"])
		}
		if lr["id"] != "rr-breach-rt" || lr["status"] != "failed" || lr["inProgress"] != false {
			t.Errorf("latestRemediation = %+v, want id=rr-breach-rt status=failed inProgress=false", lr)
		}
	})
}

func TestGetSLABreaches_NoRemediationAttempt_LatestRemediationAbsent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('breach-rt2', 'BREACH-RT2')`)
		breachedAt := time.Now().Add(-1 * time.Hour)
		seedFindingSLA(t, pool, "fs-breach-rt2", "breach-rt2", "windows-smbv1-disabled", "High", "breached", time.Now().Add(-2*time.Hour), &breachedAt)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/sla/breaches", nil)
		w := httptest.NewRecorder()
		h.GetSLABreaches(w, req)

		var got []map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1", len(got))
		}
		if _, present := got[0]["latestRemediation"]; present {
			t.Errorf("latestRemediation present = %v, want absent", got[0]["latestRemediation"])
		}
	})
}
