package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/segprobe"
	"github.com/audspect/bas/internal/segprobe/runstore"
)

const segScenarioDir = "../../../lab/segmentation/scenarios"

// segFakeLab is a lab that cannot reach any zone, so every probe grades ERROR.
// When block is set, ApplyRules waits on it, which keeps a run in progress.
type segFakeLab struct{ block chan struct{} }

func (f *segFakeLab) Healthy(context.Context, segprobe.Zone) error { return errors.New("down") }
func (f *segFakeLab) Lookup(segprobe.Zone) (string, error)         { return "10.0.0.1", nil }
func (f *segFakeLab) TargetIP(segprobe.Zone) (string, error)       { return "10.0.0.2", nil }
func (f *segFakeLab) Probe(context.Context, segprobe.ProbeRequest) (segprobe.ProbeResult, error) {
	return segprobe.ProbeResult{}, errors.New("unused")
}
func (f *segFakeLab) FirewallEvents(context.Context, segprobe.TimeWindow) ([]segprobe.FirewallEvent, bool, error) {
	return nil, false, nil
}
func (f *segFakeLab) ApplyRules(context.Context, string) error {
	if f.block != nil {
		<-f.block
	}
	return nil
}

func segRouter(h *Handler) http.Handler {
	r := chi.NewRouter()
	r.With(auth.RequirePermission(auth.CanViewSegmentation)).Get("/api/segmentation/packs", h.ListSegmentationPacks)
	r.With(auth.RequirePermission(auth.CanRunSegmentation)).Post("/api/segmentation/runs", h.SubmitSegmentationRun)
	r.With(auth.RequirePermission(auth.CanViewSegmentation)).Get("/api/segmentation/runs", h.ListSegmentationRuns)
	r.With(auth.RequirePermission(auth.CanViewSegmentation)).Get("/api/segmentation/runs/{id}", h.GetSegmentationRun)
	return r
}

// segHandler builds a handler on the shared test database. A nil lab leaves the
// lab unconfigured.
func segHandler(t *testing.T, lab *segFakeLab) (*Handler, *segprobe.Service) {
	t.Helper()
	ctx := context.Background()
	if err := db.EnsureSegmentationSchema(ctx, sharedDB.Pool); err != nil {
		t.Fatal(err)
	}
	store := runstore.New(sharedDB.Pool)
	h := &Handler{db: sharedDB.Pool}
	if lab == nil {
		return h.WithSegmentation(nil, store), nil
	}
	svc := segprobe.NewService(store, segScenarioDir, func() segprobe.LabProvider { return lab })
	return h.WithSegmentation(svc, store), svc
}

func segReq(t *testing.T, h http.Handler, method, path string, body any, role auth.Role, user string) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
	if role != "" {
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: user, Role: role}))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSegmentation_PacksListedForAnalyst(t *testing.T) {
	h, _ := segHandler(t, &segFakeLab{})
	rec := segReq(t, segRouter(h), http.MethodGet, "/api/segmentation/packs", nil, auth.RoleAnalyst, "alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Packs   []map[string]any `json:"packs"`
		Enabled bool             `json:"enabled"`
		CanRun  bool             `json:"can_run"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Packs) != 3 || !out.Enabled {
		t.Fatalf("packs = %d enabled = %v", len(out.Packs), out.Enabled)
	}
	if out.CanRun {
		t.Fatal("an analyst was told they can run segmentation; only admins can")
	}
	admin := segReq(t, segRouter(h), http.MethodGet, "/api/segmentation/packs", nil, auth.RoleAdmin, "admin1")
	if err := json.Unmarshal(admin.Body.Bytes(), &out); err != nil || !out.CanRun {
		t.Fatalf("admin can_run = %v, err %v", out.CanRun, err)
	}
}

func TestSegmentation_AnalystCannotRunAndViewerCannotRead(t *testing.T) {
	h, _ := segHandler(t, &segFakeLab{})
	r := segRouter(h)
	if rec := segReq(t, r, http.MethodPost, "/api/segmentation/runs", map[string]any{"pack": "swift-isolation"}, auth.RoleAnalyst, "alice"); rec.Code != http.StatusForbidden {
		t.Fatalf("analyst run: got %d, want 403", rec.Code)
	}
	if rec := segReq(t, r, http.MethodGet, "/api/segmentation/runs", nil, auth.RoleViewer, "vic"); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer read: got %d, want 403", rec.Code)
	}
}

func TestSegmentation_AdminRunsAndAnalystReadsStoredVerdicts(t *testing.T) {
	h, svc := segHandler(t, &segFakeLab{})
	r := segRouter(h)
	rec := segReq(t, r, http.MethodPost, "/api/segmentation/runs", map[string]any{"pack": "swift-isolation"}, auth.RoleAdmin, "admin1")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("admin run: got %d %s", rec.Code, rec.Body.String())
	}
	var started runstore.Run
	if err := json.Unmarshal(rec.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	svc.Wait()

	get := segReq(t, r, http.MethodGet, "/api/segmentation/runs/"+started.ID, nil, auth.RoleAnalyst, "alice")
	if get.Code != http.StatusOK {
		t.Fatalf("read: got %d %s", get.Code, get.Body.String())
	}
	var out struct {
		Run    runstore.Run        `json:"run"`
		Probes []runstore.ProbeRow `json:"probes"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Run.Status != "completed" || out.Run.Runs != segprobe.RunsPerPack {
		t.Fatalf("run = %+v", out.Run)
	}
	if len(out.Probes) != 3*segprobe.RunsPerPack {
		t.Fatalf("probes = %d, want %d", len(out.Probes), 3*segprobe.RunsPerPack)
	}
	for _, p := range out.Probes {
		if p.Verdict != "ERROR" {
			t.Fatalf("probe %s stored as %s; the unreachable fake must store ERROR, not a softened verdict", p.ProbeID, p.Verdict)
		}
	}
}

func TestSegmentation_UnknownPackAndBusyAndDisabled(t *testing.T) {
	r := func(h *Handler) http.Handler { return segRouter(h) }

	h, _ := segHandler(t, &segFakeLab{})
	if rec := segReq(t, r(h), http.MethodPost, "/api/segmentation/runs", map[string]any{"pack": "../../etc"}, auth.RoleAdmin, "admin1"); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown pack: got %d, want 400", rec.Code)
	}

	lab := &segFakeLab{block: make(chan struct{})}
	hb, svc := segHandler(t, lab)
	if rec := segReq(t, r(hb), http.MethodPost, "/api/segmentation/runs", map[string]any{"pack": "swift-isolation"}, auth.RoleAdmin, "admin1"); rec.Code != http.StatusAccepted {
		t.Fatalf("first run: got %d", rec.Code)
	}
	if rec := segReq(t, r(hb), http.MethodPost, "/api/segmentation/runs", map[string]any{"pack": "cde-atm-isolation"}, auth.RoleAdmin, "admin1"); rec.Code != http.StatusConflict {
		t.Fatalf("busy run: got %d, want 409", rec.Code)
	}
	close(lab.block)
	svc.Wait()

	hd, _ := segHandler(t, nil)
	if rec := segReq(t, r(hd), http.MethodPost, "/api/segmentation/runs", map[string]any{"pack": "swift-isolation"}, auth.RoleAdmin, "admin1"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled lab: got %d, want 503", rec.Code)
	}
}

func TestSegmentation_MissingRunIsNotFound(t *testing.T) {
	h, _ := segHandler(t, &segFakeLab{})
	r := segRouter(h)
	for _, id := range []string{"not-a-uuid", "00000000-0000-0000-0000-000000000000"} {
		if rec := segReq(t, r, http.MethodGet, "/api/segmentation/runs/"+id, nil, auth.RoleAnalyst, "alice"); rec.Code != http.StatusNotFound {
			t.Fatalf("run %q: got %d, want 404", id, rec.Code)
		}
	}
}
