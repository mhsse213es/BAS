package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// multipartEvidenceReq builds a POST /api/verifications/{id}/evidence request
// carrying one "file" field (and an optional displayName field).
func multipartEvidenceReq(vid, filename, displayName string, content []byte) *http.Request {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if filename != "" {
		fw, _ := w.CreateFormFile("file", filename)
		fw.Write(content)
	}
	if displayName != "" {
		w.WriteField("displayName", displayName)
	}
	w.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/verifications/"+vid+"/evidence", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return withURLParam(req, "id", vid)
}

// withBearerToken adds a valid JWT to an already-built request (unlike
// authedRequest, which only builds a request from scratch) — needed here so
// a multipart upload's body/Content-Type/chi URL param survive alongside
// authentication. UploadVerificationEvidence/DeleteEvidence unconditionally
// dereference auth.ClaimsFrom's result (same pattern as the already-tested
// CreateVerification), so — matching how the router always wraps these
// routes in auth.Middleware in production — these must go through
// callAuthed, never called directly with no auth context.
func withBearerToken(t *testing.T, req *http.Request, role auth.Role, userID string) *http.Request {
	t.Helper()
	token, err := auth.GenerateToken(userID, role, testJWTSecret, time.Hour)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// seedVerification creates one verification record via the real
// CreateVerification handler and returns its id — the shared setup every
// evidence test needs (evidence hangs off a verification, not a run).
func seedVerification(t *testing.T, h *Handler, pool *pgxpool.Pool, scenarioID, runID, agentID string) string {
	t.Helper()
	seedRunForScenario(t, pool, runID, agentID, scenarioID)
	uid := seedUser(t, pool, "ev-seed-"+runID, "pw-Password1!", "admin", true)
	rec := callAuthed(h.CreateVerification, createVerificationReq(t, map[string]any{
		"runId": runID, "expectationId": "exp-manual", "result": "Detected",
	}, auth.RoleAdmin, uid))
	if rec.Code != http.StatusCreated {
		t.Fatalf("seedVerification: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	return out.ID
}

func TestUploadVerificationEvidence_NilStore503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.UploadVerificationEvidence(rec, multipartEvidenceReq("v1", "a.txt", "", []byte("hi")))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})
}

func TestUploadVerificationEvidence_VerificationNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newVerificationHandler(t, pool, scenario.NewEngine(t.TempDir()))
		rec := httptest.NewRecorder()
		h.UploadVerificationEvidence(rec, multipartEvidenceReq("nope", "a.txt", "", []byte("hi")))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestUploadVerificationEvidence_InvalidMultipartForm pins the
// ParseMultipartForm error branch: a request claiming multipart/form-data
// but carrying a body that doesn't match the declared boundary.
func TestUploadVerificationEvidence_InvalidMultipartForm(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := verificationScenario(t, "uve-badform-sc")
		h := newVerificationHandler(t, pool, engine)
		vid := seedVerification(t, h, pool, sc.ID, "uve-badform-run", "uve-badform-agent")

		req := httptest.NewRequest(http.MethodPost, "/api/verifications/"+vid+"/evidence", bytes.NewReader([]byte("not-multipart-body")))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=doesnotmatch")
		req = withURLParam(req, "id", vid)

		rec := httptest.NewRecorder()
		h.UploadVerificationEvidence(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestUploadVerificationEvidence_MissingFileField(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := verificationScenario(t, "uve-missing-sc")
		h := newVerificationHandler(t, pool, engine)
		vid := seedVerification(t, h, pool, sc.ID, "uve-missing-run", "uve-missing-agent")

		rec := httptest.NewRecorder()
		h.UploadVerificationEvidence(rec, multipartEvidenceReq(vid, "", "", nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

// TestUploadVerificationEvidence_ExceedsSizeLimit pins the 25 MiB cap
// (maxEvidenceBytes) with a real over-limit body.
func TestUploadVerificationEvidence_ExceedsSizeLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := verificationScenario(t, "uve-toobig-sc")
		h := newVerificationHandler(t, pool, engine)
		vid := seedVerification(t, h, pool, sc.ID, "uve-toobig-run", "uve-toobig-agent")

		big := make([]byte, maxEvidenceBytes+1024)
		rec := httptest.NewRecorder()
		h.UploadVerificationEvidence(rec, multipartEvidenceReq(vid, "big.bin", "", big))
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestUploadVerificationEvidence_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := verificationScenario(t, "uve-ok-sc")
		h := newVerificationHandler(t, pool, engine)
		vid := seedVerification(t, h, pool, sc.ID, "uve-ok-run", "uve-ok-agent")

		content := []byte("sentinel alert export, KQL query results\n")
		uid := seedUser(t, pool, "uve-ok-user", "pw-Password1!", "admin", true)
		req := withBearerToken(t, multipartEvidenceReq(vid, "alert.csv", "Sentinel Export", content), auth.RoleAdmin, uid)
		rec := callAuthed(h.UploadVerificationEvidence, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			ID               string `json:"id"`
			OriginalFilename string `json:"originalFilename"`
			DisplayFilename  string `json:"displayFilename"`
			ContentHash      string `json:"contentHash"`
			Size             int64  `json:"size"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		wantHash := sha256.Sum256(content)
		if out.ContentHash != hex.EncodeToString(wantHash[:]) {
			t.Errorf("contentHash = %q, want sha256 of the uploaded bytes", out.ContentHash)
		}
		if out.DisplayFilename != "Sentinel Export" {
			t.Errorf("displayFilename = %q, want the explicit override", out.DisplayFilename)
		}
		if out.Size != int64(len(content)) {
			t.Errorf("size = %d, want %d", out.Size, len(content))
		}
	})
}

func TestListVerificationEvidence_NilStore503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.ListVerificationEvidence(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "v1"))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})
}

func TestListVerificationEvidence_EmptyReturnsArray(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := verificationScenario(t, "lve-empty-sc")
		h := newVerificationHandler(t, pool, engine)
		vid := seedVerification(t, h, pool, sc.ID, "lve-empty-run", "lve-empty-agent")

		rec := httptest.NewRecorder()
		h.ListVerificationEvidence(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", vid))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out struct {
			Evidence []map[string]any `json:"evidence"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Evidence == nil || len(out.Evidence) != 0 {
			t.Fatalf("evidence = %v, want an empty (non-nil) array", out.Evidence)
		}
	})
}

func TestListVerificationEvidence_ExcludesSoftDeleted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := verificationScenario(t, "lve-del-sc")
		h := newVerificationHandler(t, pool, engine)
		vid := seedVerification(t, h, pool, sc.ID, "lve-del-run", "lve-del-agent")

		uid := seedUser(t, pool, "lve-del-user", "pw-Password1!", "admin", true)
		callAuthed(h.UploadVerificationEvidence, withBearerToken(t, multipartEvidenceReq(vid, "keep.txt", "", []byte("keep")), auth.RoleAdmin, uid))
		up2 := callAuthed(h.UploadVerificationEvidence, withBearerToken(t, multipartEvidenceReq(vid, "delete-me.txt", "", []byte("gone")), auth.RoleAdmin, uid))
		var ev2 struct {
			ID string `json:"id"`
		}
		json.Unmarshal(up2.Body.Bytes(), &ev2)

		delRec := callAuthed(h.DeleteEvidence, withBearerToken(t, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", ev2.ID), auth.RoleAdmin, uid))
		if delRec.Code != http.StatusOK {
			t.Fatalf("delete: status = %d, want 200, body = %s", delRec.Code, delRec.Body.String())
		}

		listRec := httptest.NewRecorder()
		h.ListVerificationEvidence(listRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", vid))
		var out struct {
			Evidence []map[string]any `json:"evidence"`
		}
		json.Unmarshal(listRec.Body.Bytes(), &out)
		if len(out.Evidence) != 1 {
			t.Fatalf("evidence = %+v, want 1 entry (soft-deleted one excluded)", out.Evidence)
		}
	})
}

func TestDownloadEvidence_NilStore503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.DownloadEvidence(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "e1"))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})
}

func TestDownloadEvidence_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newVerificationHandler(t, pool, scenario.NewEngine(t.TempDir()))
		rec := httptest.NewRecorder()
		h.DownloadEvidence(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestDownloadEvidence_Success pins the streamed bytes plus the integrity
// headers (X-Content-SHA256/X-Hash-Algorithm) a client uses to re-verify the
// download, and the Content-Disposition filename falling back to
// OriginalFilename when no DisplayFilename override was set.
func TestDownloadEvidence_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := verificationScenario(t, "dl-ok-sc")
		h := newVerificationHandler(t, pool, engine)
		vid := seedVerification(t, h, pool, sc.ID, "dl-ok-run", "dl-ok-agent")

		content := []byte("evidence bytes for download roundtrip")
		uid := seedUser(t, pool, "dl-ok-user", "pw-Password1!", "admin", true)
		upRec := callAuthed(h.UploadVerificationEvidence, withBearerToken(t, multipartEvidenceReq(vid, "proof.txt", "", content), auth.RoleAdmin, uid))
		var ev struct {
			ID string `json:"id"`
		}
		json.Unmarshal(upRec.Body.Bytes(), &ev)

		rec := httptest.NewRecorder()
		h.DownloadEvidence(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", ev.ID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		if !bytes.Equal(rec.Body.Bytes(), content) {
			t.Errorf("downloaded body = %q, want %q", rec.Body.String(), content)
		}
		wantHash := sha256.Sum256(content)
		if rec.Header().Get("X-Content-SHA256") != hex.EncodeToString(wantHash[:]) {
			t.Errorf("X-Content-SHA256 = %q", rec.Header().Get("X-Content-SHA256"))
		}
		if rec.Header().Get("X-Hash-Algorithm") == "" {
			t.Error("X-Hash-Algorithm header missing")
		}
		if rec.Header().Get("Content-Disposition") == "" {
			t.Error("Content-Disposition header missing")
		}
	})
}

func TestDeleteEvidence_NilStore503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.DeleteEvidence(rec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", "e1"))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})
}

func TestDeleteEvidence_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newVerificationHandler(t, pool, scenario.NewEngine(t.TempDir()))
		rec := httptest.NewRecorder()
		h.DeleteEvidence(rec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestDeleteEvidence_SoftDeleteThenDownloadIs404 pins the soft-delete
// contract end to end: after deletion, DownloadEvidence (which excludes
// ev.Deleted) reports not-found even though the row and blob still exist for
// audit retention.
func TestDeleteEvidence_SoftDeleteThenDownloadIs404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := verificationScenario(t, "de-softdel-sc")
		h := newVerificationHandler(t, pool, engine)
		vid := seedVerification(t, h, pool, sc.ID, "de-softdel-run", "de-softdel-agent")

		uid := seedUser(t, pool, "de-softdel-user", "pw-Password1!", "admin", true)
		upRec := callAuthed(h.UploadVerificationEvidence, withBearerToken(t, multipartEvidenceReq(vid, "temp.txt", "", []byte("temp")), auth.RoleAdmin, uid))
		var ev struct {
			ID string `json:"id"`
		}
		json.Unmarshal(upRec.Body.Bytes(), &ev)

		delRec := callAuthed(h.DeleteEvidence, withBearerToken(t, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", ev.ID), auth.RoleAdmin, uid))
		if delRec.Code != http.StatusOK {
			t.Fatalf("delete: status = %d, want 200", delRec.Code)
		}
		var delOut map[string]any
		json.Unmarshal(delRec.Body.Bytes(), &delOut)
		if delOut["deleted"] != true {
			t.Errorf("delete response = %v, want deleted:true", delOut)
		}

		dlRec := httptest.NewRecorder()
		h.DownloadEvidence(dlRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", ev.ID))
		if dlRec.Code != http.StatusNotFound {
			t.Fatalf("download after soft-delete: status = %d, want 404", dlRec.Code)
		}

		var deletedBy string
		if err := pool.QueryRow(context.Background(),
			`SELECT COALESCE(deleted_by,'') FROM verification_evidence WHERE id=$1`, ev.ID,
		).Scan(&deletedBy); err != nil {
			t.Fatalf("query deleted_by: %v", err)
		}
		if deletedBy == "" {
			t.Error("deleted_by not stamped")
		}
	})
}
