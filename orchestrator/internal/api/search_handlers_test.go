package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/search"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSearchSelect_NoClaimsUnauthorized(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, testJWTSecret)
	req := httptest.NewRequest(http.MethodPost, "/api/search/select", nil)
	rec := httptest.NewRecorder()
	h.SearchSelect(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no claims in context)", rec.Code)
	}
}

func TestSearchFavorite_MalformedBody(t *testing.T) {
	userID := "does-not-matter-claims-check-runs-first"
	req := authedRequest(t, http.MethodPost, "/api/search/favorite", bytes.NewReader([]byte("{not json")), auth.RoleViewer, userID)
	h := New(nil, ws.NewHub(), nil, testJWTSecret)
	if rec := callAuthed(h.SearchFavorite, req); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestSearchSelect_InsertsOneRowPerCall(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		userID := seedUser(t, pool, "select-user", "password123", "viewer", true)

		body, _ := json.Marshal(map[string]string{"docType": "scenario", "sourceId": "s1"})
		req1 := authedRequest(t, http.MethodPost, "/api/search/select", bytes.NewReader(body), auth.RoleViewer, userID)
		if rec := callAuthed(h.SearchSelect, req1); rec.Code != http.StatusOK {
			t.Fatalf("first select: status = %d, want 200", rec.Code)
		}
		req2 := authedRequest(t, http.MethodPost, "/api/search/select", bytes.NewReader(body), auth.RoleViewer, userID)
		if rec := callAuthed(h.SearchSelect, req2); rec.Code != http.StatusOK {
			t.Fatalf("second select: status = %d, want 200", rec.Code)
		}

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM search_selections WHERE user_id=$1 AND doc_type='scenario' AND source_id='s1'`,
			userID).Scan(&count); err != nil {
			t.Fatalf("count selections: %v", err)
		}
		if count != 2 {
			t.Errorf("selection row count = %d, want 2 (repeat calls accumulate, they don't upsert)", count)
		}
	})
}

func TestSearchFavorite_TogglesOnRepeatedCalls(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		userID := seedUser(t, pool, "fav-user", "password123", "viewer", true)
		body, _ := json.Marshal(map[string]string{"docType": "scenario", "sourceId": "s1"})

		req1 := authedRequest(t, http.MethodPost, "/api/search/favorite", bytes.NewReader(body), auth.RoleViewer, userID)
		rec1 := callAuthed(h.SearchFavorite, req1)
		var res1 map[string]bool
		if err := json.Unmarshal(rec1.Body.Bytes(), &res1); err != nil {
			t.Fatalf("decode first response: %v", err)
		}
		if !res1["favorited"] {
			t.Fatalf("first toggle: favorited = %v, want true", res1["favorited"])
		}

		req2 := authedRequest(t, http.MethodPost, "/api/search/favorite", bytes.NewReader(body), auth.RoleViewer, userID)
		rec2 := callAuthed(h.SearchFavorite, req2)
		var res2 map[string]bool
		if err := json.Unmarshal(rec2.Body.Bytes(), &res2); err != nil {
			t.Fatalf("decode second response: %v", err)
		}
		if res2["favorited"] {
			t.Fatalf("second toggle: favorited = %v, want false", res2["favorited"])
		}
	})
}

func TestSearchRecents_ReturnsFavoritesBeforeRecents(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		userID := seedUser(t, pool, "recents-handler-user", "password123", "viewer", true)

		if _, err := pool.Exec(ctx,
			`INSERT INTO search_documents (doc_type, source_id, title, description, tags, search_vector)
			 VALUES ('scenario','h-fav','Handler Favorite','','{}', to_tsvector('english','Handler Favorite')),
			        ('scenario','h-rec','Handler Recent','','{}', to_tsvector('english','Handler Recent'))`); err != nil {
			t.Fatalf("seed search_documents: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO search_favorites (user_id, doc_type, source_id) VALUES ($1,'scenario','h-fav')`, userID); err != nil {
			t.Fatalf("seed favorite: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO search_selections (user_id, doc_type, source_id) VALUES ($1,'scenario','h-rec')`, userID); err != nil {
			t.Fatalf("seed selection: %v", err)
		}

		req := authedRequest(t, http.MethodGet, "/api/search/recents", nil, auth.RoleViewer, userID)
		rec := callAuthed(h.SearchRecents, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var results []search.Document
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("results = %+v, want 2 (one favorite, one recent)", results)
		}
		if results[0].SourceID != "h-fav" || !results[0].Favorited {
			t.Errorf("results[0] = %+v, want h-fav favorited first", results[0])
		}
		if results[1].SourceID != "h-rec" || results[1].Favorited {
			t.Errorf("results[1] = %+v, want h-rec not favorited", results[1])
		}
	})
}

func seedSearchDocsForRBACTest(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO search_documents (doc_type, source_id, title, description, tags, search_vector) VALUES
		   ('scenario', 'rbac-scn-1', 'RBAC Test Scenario', '', '{}', to_tsvector('english','RBAC Test Scenario')),
		   ('detection_connector', 'rbac-dc-1', 'RBAC Test Detection Connector', 'provider: splunk', '{splunk}', to_tsvector('english','RBAC Test Detection Connector')),
		   ('action_connector', 'rbac-ac-1', 'RBAC Test Action Connector', 'provider: crowdstrike', '{crowdstrike}', to_tsvector('english','RBAC Test Action Connector'))`); err != nil {
		t.Fatalf("seed search_documents: %v", err)
	}
}

func hasDocType(docs []search.Document, docType string) bool {
	for _, d := range docs {
		if d.DocType == docType {
			return true
		}
	}
	return false
}

func TestSearch_NonAdminNeverSeesConnectorResults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedSearchDocsForRBACTest(t, pool)
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		userID := seedUser(t, pool, "rbac-viewer", "password123", "viewer", true)

		req := authedRequest(t, http.MethodGet, "/api/search?q=RBAC+Test", nil, auth.RoleViewer, userID)
		rec := callAuthed(h.Search, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var results []search.Document
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if hasDocType(results, "detection_connector") {
			t.Errorf("results %+v included a detection_connector doc for a viewer without CanListDetectionConnectors", results)
		}
		if hasDocType(results, "action_connector") {
			t.Errorf("results %+v included an action_connector doc for a viewer without CanListResponseConnectors", results)
		}
		if !hasDocType(results, "scenario") {
			t.Errorf("results %+v dropped the unrestricted scenario doc -- filtering must not over-filter", results)
		}
	})
}

func TestSearch_AdminSeesConnectorResults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedSearchDocsForRBACTest(t, pool)
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		userID := seedUser(t, pool, "rbac-admin", "password123", "admin", true)

		req := authedRequest(t, http.MethodGet, "/api/search?q=RBAC+Test", nil, auth.RoleAdmin, userID)
		rec := callAuthed(h.Search, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var results []search.Document
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if !hasDocType(results, "detection_connector") {
			t.Errorf("results %+v missing detection_connector doc for an admin", results)
		}
		if !hasDocType(results, "action_connector") {
			t.Errorf("results %+v missing action_connector doc for an admin", results)
		}
	})
}

func TestSearch_BrowseModeConnectorTypeEmptyForNonAdmin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedSearchDocsForRBACTest(t, pool)
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		userID := seedUser(t, pool, "rbac-viewer-browse", "password123", "viewer", true)

		req := authedRequest(t, http.MethodGet, "/api/search?q=type:detection_connector", nil, auth.RoleViewer, userID)
		rec := callAuthed(h.Search, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var results []search.Document
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if len(results) != 0 {
			t.Fatalf("results = %+v, want empty (non-admin browsing type:detection_connector)", results)
		}
	})
}

func TestSearchOperators_ReturnsSupportedList(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, testJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/search/operators", nil)
	rec := httptest.NewRecorder()
	h.SearchOperators(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string][]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	want := []string{"type"}
	if !reflect.DeepEqual(body["operators"], want) {
		t.Errorf("operators = %+v, want %+v", body["operators"], want)
	}
}
