package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/actions"
	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func actionsHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
}

func actionsConfigReq(body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/actions/configs", bytes.NewReader(b))
}

func TestListResponseConnectors_EmptyAndPopulated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		rec := httptest.NewRecorder()
		h.ListResponseConnectors(rec, httptest.NewRequest(http.MethodGet, "/api/actions/configs", nil))
		var empty []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &empty)
		if len(empty) != 0 {
			t.Fatalf("expected 0 connectors, got %d", len(empty))
		}

		createRec := httptest.NewRecorder()
		h.CreateResponseConnector(createRec, actionsConfigReq(map[string]any{
			"name": "Prod CrowdStrike", "provider": "crowdstrike", "baseUrl": "https://api.crowdstrike.com",
		}))
		if createRec.Code != http.StatusOK {
			t.Fatalf("create: status = %d, want 200, body = %s", createRec.Code, createRec.Body.String())
		}

		listRec := httptest.NewRecorder()
		h.ListResponseConnectors(listRec, httptest.NewRequest(http.MethodGet, "/api/actions/configs", nil))
		var out []map[string]any
		json.Unmarshal(listRec.Body.Bytes(), &out)
		if len(out) != 1 || out[0]["name"] != "Prod CrowdStrike" || out[0]["provider"] != "crowdstrike" {
			t.Fatalf("out = %+v, want 1 entry named Prod CrowdStrike/crowdstrike", out)
		}
	})
}

func TestCreateResponseConnector_ValidationErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		cases := []struct {
			name string
			body map[string]any
		}{
			{"missing name", map[string]any{"provider": "crowdstrike"}},
			{"missing provider", map[string]any{"name": "x"}},
			{"invalid provider", map[string]any{"name": "x", "provider": "sentinelone"}},
		}
		for _, c := range cases {
			rec := httptest.NewRecorder()
			h.CreateResponseConnector(rec, actionsConfigReq(c.body))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400", c.name, rec.Code)
			}
		}
	})
}

func TestUpdateResponseConnector_PreservesMaskedSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		createRec := httptest.NewRecorder()
		h.CreateResponseConnector(createRec, actionsConfigReq(map[string]any{
			"name": "x", "provider": "crowdstrike", "clientSecret": "real-secret",
		}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)

		b, _ := json.Marshal(map[string]any{"name": "x-renamed", "clientSecret": "***"})
		req := withURLParam(httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(b)), "id", created.ID)
		rec := httptest.NewRecorder()
		h.UpdateResponseConnector(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}

		var name, secret string
		pool.QueryRow(context.Background(),
			`SELECT name, client_secret FROM action_connectors WHERE id=$1`, created.ID,
		).Scan(&name, &secret)
		if name != "x-renamed" {
			t.Errorf("name = %q, want x-renamed", name)
		}
		if secret != "real-secret" {
			t.Errorf("client_secret = %q, want the original secret preserved", secret)
		}
	})
}

func TestDeleteResponseConnector_NotFoundAndSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		notFoundRec := httptest.NewRecorder()
		h.DeleteResponseConnector(notFoundRec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", "nope"))
		if notFoundRec.Code != http.StatusNotFound {
			t.Fatalf("not found: status = %d, want 404", notFoundRec.Code)
		}

		createRec := httptest.NewRecorder()
		h.CreateResponseConnector(createRec, actionsConfigReq(map[string]any{"name": "x", "provider": "microsoft_defender"}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)

		delRec := httptest.NewRecorder()
		h.DeleteResponseConnector(delRec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", created.ID))
		if delRec.Code != http.StatusOK {
			t.Fatalf("delete: status = %d, want 200", delRec.Code)
		}
		var n int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM action_connectors WHERE id=$1`, created.ID).Scan(&n)
		if n != 0 {
			t.Fatalf("expected the connector to be gone, found %d rows", n)
		}
	})
}

func TestTestResponseConnector_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		rec := httptest.NewRecorder()
		h.TestResponseConnector(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// fakeActionVendorClient mirrors internal/actions' own test double — this
// package tests the HTTP layer's wiring (validation, persistence, audit),
// not vendor dispatch logic (already covered in internal/actions and
// internal/vendors/*).
type fakeActionVendorClient struct {
	resolveDeviceErr error
	isolateID        string
}

func (f *fakeActionVendorClient) ResolveDevice(ctx context.Context, hostname string) (string, error) {
	if f.resolveDeviceErr != nil {
		return "", f.resolveDeviceErr
	}
	return "device-fake-1", nil
}
func (f *fakeActionVendorClient) Isolate(ctx context.Context, deviceID string) (string, error) {
	return f.isolateID, nil
}
func (f *fakeActionVendorClient) Release(ctx context.Context, deviceID string) (string, error) {
	return "release-id", nil
}
func (f *fakeActionVendorClient) KillProcess(ctx context.Context, deviceID string, pid int) (string, error) {
	return "kill-id", nil
}
func (f *fakeActionVendorClient) QuarantineFile(ctx context.Context, deviceID, param string) (string, error) {
	return "quarantine-id", nil
}

func seedActionConnector(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(),
		`INSERT INTO action_connectors (name, provider, enabled, base_url, client_id, client_secret)
		 VALUES ('test-cs', 'crowdstrike', true, 'https://api.crowdstrike.com', 'c1', 's1') RETURNING id`,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seed action_connectors: %v", err)
	}
	return id
}

func seedTestAgent(t *testing.T, pool *pgxpool.Pool, hostname string) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO agents (agent_id, hostname) VALUES ($1, $2) ON CONFLICT (agent_id) DO NOTHING`,
		"agent-"+hostname, hostname)
	if err != nil {
		t.Fatalf("seed agents: %v", err)
	}
}

func actionRunReq(body map[string]any) *http.Request {
	data, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/actions/run", bytes.NewReader(data))
}

func TestExecuteResponseAction_Isolate_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		h.actionVendorClient = func(cfg actions.ConnectorConfig) (actions.VendorClient, error) {
			return &fakeActionVendorClient{isolateID: "trace-xyz"}, nil
		}
		connID := seedActionConnector(t, pool)
		seedTestAgent(t, pool, "WIN-TEST-01")

		req := authedRequest(t, http.MethodPost, "/api/actions/run", bytes.NewReader(mustJSON(t, map[string]any{
			"type": actions.TypeIsolate, "hostname": "WIN-TEST-01", "connectorId": connID,
			"reason": "confirmed ransomware simulation success",
		})), auth.RoleAdmin, "admin-1")
		w := callAuthed(h.ExecuteResponseAction, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			ID              string `json:"id"`
			Status          string `json:"status"`
			VendorRequestID string `json:"vendorRequestId"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Status != actions.StatusCompleted {
			t.Fatalf("status = %q, want %q", resp.Status, actions.StatusCompleted)
		}
		if resp.VendorRequestID != "trace-xyz" {
			t.Fatalf("vendorRequestId = %q, want trace-xyz", resp.VendorRequestID)
		}

		var persistedStatus, persistedRequestedBy string
		if err := pool.QueryRow(context.Background(),
			`SELECT status, requested_by FROM action_requests WHERE id=$1`, resp.ID,
		).Scan(&persistedStatus, &persistedRequestedBy); err != nil {
			t.Fatalf("action_requests row not found: %v", err)
		}
		if persistedStatus != actions.StatusCompleted {
			t.Fatalf("persisted status = %q, want completed", persistedStatus)
		}
		if persistedRequestedBy != "admin-1" {
			t.Fatalf("persisted requested_by = %q, want admin-1", persistedRequestedBy)
		}
	})
}

func TestExecuteResponseAction_UnknownHostname_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		h.actionVendorClient = func(cfg actions.ConnectorConfig) (actions.VendorClient, error) {
			return &fakeActionVendorClient{}, nil
		}
		connID := seedActionConnector(t, pool)

		w := httptest.NewRecorder()
		h.ExecuteResponseAction(w, actionRunReq(map[string]any{
			"type": actions.TypeIsolate, "hostname": "NOT-AN-ENROLLED-AGENT", "connectorId": connID,
			"reason": "test",
		}))

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
		}
	})
}

func TestExecuteResponseAction_MissingReason_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		connID := seedActionConnector(t, pool)
		seedTestAgent(t, pool, "WIN-TEST-02")

		w := httptest.NewRecorder()
		h.ExecuteResponseAction(w, actionRunReq(map[string]any{
			"type": actions.TypeIsolate, "hostname": "WIN-TEST-02", "connectorId": connID,
		}))

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
		}
	})
}

func TestExecuteResponseAction_VendorFailure_PersistsFailedStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		h.actionVendorClient = func(cfg actions.ConnectorConfig) (actions.VendorClient, error) {
			return &fakeActionVendorClient{resolveDeviceErr: context.DeadlineExceeded}, nil
		}
		connID := seedActionConnector(t, pool)
		seedTestAgent(t, pool, "WIN-TEST-03")

		w := httptest.NewRecorder()
		h.ExecuteResponseAction(w, actionRunReq(map[string]any{
			"type": actions.TypeIsolate, "hostname": "WIN-TEST-03", "connectorId": connID,
			"reason": "test",
		}))

		// A vendor-level failure is still a 200 with status=failed in the
		// body — matching this codebase's existing TestDetectionConnector
		// convention (respond({"ok": false, ...}) rather than an HTTP error
		// status) — because the request itself was well-formed; only the
		// vendor call failed.
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Status string `json:"status"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Status != actions.StatusFailed {
			t.Fatalf("status = %q, want failed", resp.Status)
		}
	})
}

func TestListResponseActions_ReturnsPersistedRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		h.actionVendorClient = func(cfg actions.ConnectorConfig) (actions.VendorClient, error) {
			return &fakeActionVendorClient{isolateID: "trace-list-1"}, nil
		}
		connID := seedActionConnector(t, pool)
		seedTestAgent(t, pool, "WIN-TEST-04")

		h.ExecuteResponseAction(httptest.NewRecorder(), actionRunReq(map[string]any{
			"type": actions.TypeIsolate, "hostname": "WIN-TEST-04", "connectorId": connID,
			"reason": "test", "runId": "run-abc",
		}))

		w := httptest.NewRecorder()
		h.ListResponseActions(w, httptest.NewRequest(http.MethodGet, "/api/actions?runId=run-abc", nil))

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var rows []map[string]any
		json.Unmarshal(w.Body.Bytes(), &rows)
		if len(rows) != 1 {
			t.Fatalf("rows = %d, want 1", len(rows))
		}
		if rows[0]["runId"] != "run-abc" {
			t.Fatalf("rows[0].runId = %v, want run-abc", rows[0]["runId"])
		}
	})
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}
