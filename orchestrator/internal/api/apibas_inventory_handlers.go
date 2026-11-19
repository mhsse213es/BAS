package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/apibas/openapi"
	"github.com/audspect/bas/internal/db"
)

// Endpoint inventory: the parsed shape of a target's OpenAPI specification, stored per target as numbered versions. The raw
// document is never stored (see db.APIBASInventory). An inventory lists candidate test classes; it does not widen the target's
// scope, select scenarios or start a job, and the suggested scope it shows is advice for a person to apply through the target.

const (
	// maxListedChanges and maxListedDrift cap how many entries a response lists. Totals are always given.
	maxListedChanges = 200
	maxListedDrift   = 500
	maxObservedRoute = 20000
)

var observedMethod = regexp.MustCompile(`^[A-Z]{3,7}$`)

func capped[T any](in []T, n int) []T {
	if len(in) > n {
		return in[:n]
	}
	return in
}

func classCounts(inv *openapi.Inventory) map[string]int {
	out := map[string]int{}
	for _, ci := range openapi.Classes {
		if n := len(inv.ByClass(ci.Class)); n > 0 {
			out[string(ci.Class)] = n
		}
	}
	return out
}

// ImportAPIBASInventory stores the OpenAPI document in the request body as the target's next inventory version. The body is the
// document itself (JSON or YAML), not a JSON wrapper.
func (h *Handler) ImportAPIBASInventory(w http.ResponseWriter, r *http.Request) {
	actor, ok := apibasActor(r)
	if !ok {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	if _, err := db.GetAPIBASTarget(r.Context(), h.db, id); errors.Is(err, db.ErrAPIBASTargetNotFound) {
		jsonError(w, "target not found", http.StatusNotFound)
		return
	} else if err != nil {
		jsonError(w, "could not read target", http.StatusInternalServerError)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, openapi.MaxDocumentBytes+1))
	if err != nil {
		jsonError(w, "the document is too large", http.StatusRequestEntityTooLarge)
		return
	}
	inv, err := openapi.Import(data)
	if err != nil {
		msg := err.Error()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		jsonError(w, msg, http.StatusBadRequest)
		return
	}
	body, err := json.Marshal(inv)
	if err != nil {
		jsonError(w, "could not encode the inventory", http.StatusInternalServerError)
		return
	}
	sum := sha256.Sum256(data)
	saved, previous, unchanged, err := db.SaveAPIBASInventory(r.Context(), h.db, db.APIBASInventory{
		TargetID: id, ImportedBy: actor, SourceSHA256: hex.EncodeToString(sum[:]), SourceBytes: len(data), Title: inv.Title,
		APIVersion: inv.Version, OpenAPIVersion: inv.OpenAPIVersion, Operations: len(inv.Operations), Body: body,
	})
	if errors.Is(err, db.ErrAPIBASTargetNotFound) {
		jsonError(w, "target not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not store the inventory", http.StatusInternalServerError)
		return
	}
	if unchanged {
		apibasRespond(w, http.StatusOK, map[string]any{"version": saved.Version, "unchanged": true, "operations": saved.Operations})
		return
	}
	var prev *openapi.Inventory
	if previous.Version > 0 {
		prev = &openapi.Inventory{}
		if json.Unmarshal(previous.Body, prev) != nil {
			prev = nil
		}
	}
	changes := openapi.Compare(prev, inv)
	_ = h.auditDurable(r.Context(), actor, "apibas.inventory.import", "apibas-target:"+id, map[string]any{
		"version": saved.Version, "source_sha256": saved.SourceSHA256, "source_bytes": saved.SourceBytes, "operations": saved.Operations,
		"added": len(changes.Added), "removed": len(changes.Removed), "auth_changed": len(changes.AuthChanged),
	}, "success")
	apibasRespond(w, http.StatusCreated, map[string]any{
		"version": saved.Version, "unchanged": false, "operations": saved.Operations, "classes": classCounts(inv),
		"warnings": inv.Warnings, "suggested_scope": inv.SuggestedScope(),
		"changes": map[string]any{
			"previous_version": previous.Version,
			"added_total":      len(changes.Added), "added": capped(changes.Added, maxListedChanges),
			"removed_total": len(changes.Removed), "removed": capped(changes.Removed, maxListedChanges),
			"auth_changed_total": len(changes.AuthChanged), "auth_changed": capped(changes.AuthChanged, maxListedChanges),
		},
	})
}

// loadInventory reads a stored inventory version and decodes it. It writes the error response itself.
func (h *Handler) loadInventory(w http.ResponseWriter, r *http.Request) (db.APIBASInventory, *openapi.Inventory, bool) {
	id := chi.URLParam(r, "id")
	version := 0
	if v := r.URL.Query().Get("version"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			jsonError(w, "version must be a positive integer", http.StatusBadRequest)
			return db.APIBASInventory{}, nil, false
		}
		version = n
	}
	rec, err := db.GetAPIBASInventory(r.Context(), h.db, id, version)
	if errors.Is(err, db.ErrAPIBASInventoryNotFound) {
		jsonError(w, "no inventory for this target", http.StatusNotFound)
		return rec, nil, false
	}
	if err != nil {
		jsonError(w, "could not read the inventory", http.StatusInternalServerError)
		return rec, nil, false
	}
	inv := &openapi.Inventory{}
	if err := json.Unmarshal(rec.Body, inv); err != nil {
		jsonError(w, "the stored inventory could not be decoded", http.StatusInternalServerError)
		return rec, nil, false
	}
	return rec, inv, true
}

func inventoryMeta(rec db.APIBASInventory) map[string]any {
	return map[string]any{
		"version": rec.Version, "imported_by": rec.ImportedBy, "imported_at": rec.ImportedAt, "source_sha256": rec.SourceSHA256,
		"source_bytes": rec.SourceBytes, "title": rec.Title, "api_version": rec.APIVersion, "openapi_version": rec.OpenAPIVersion,
		"operations": rec.Operations,
	}
}

// GetAPIBASInventory returns a target's newest inventory, or the version named by ?version=. ?class= keeps only the operations
// carrying that candidate class.
func (h *Handler) GetAPIBASInventory(w http.ResponseWriter, r *http.Request) {
	rec, inv, ok := h.loadInventory(w, r)
	if !ok {
		return
	}
	ops := inv.Operations
	if c := r.URL.Query().Get("class"); c != "" {
		known := false
		for _, ci := range openapi.Classes {
			if string(ci.Class) == c {
				known = true
			}
		}
		if !known {
			jsonError(w, "unknown class", http.StatusBadRequest)
			return
		}
		ops = inv.ByClass(openapi.Class(c))
	}
	if ops == nil {
		ops = []openapi.Operation{}
	}
	meta := inventoryMeta(rec)
	meta["classes"] = classCounts(inv)
	meta["servers"] = inv.Servers
	meta["warnings"] = inv.Warnings
	meta["suggested_scope"] = inv.SuggestedScope()
	meta["listed_operations"] = ops
	apibasRespond(w, http.StatusOK, meta)
}

// ListAPIBASInventoryVersions lists a target's inventory versions, newest first, without their operations.
func (h *Handler) ListAPIBASInventoryVersions(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := db.GetAPIBASTarget(r.Context(), h.db, id); errors.Is(err, db.ErrAPIBASTargetNotFound) {
		jsonError(w, "target not found", http.StatusNotFound)
		return
	} else if err != nil {
		jsonError(w, "could not read target", http.StatusInternalServerError)
		return
	}
	recs, err := db.ListAPIBASInventoryVersions(r.Context(), h.db, id)
	if err != nil {
		jsonError(w, "could not list inventories", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		out = append(out, inventoryMeta(rec))
	}
	apibasRespond(w, http.StatusOK, map[string]any{"versions": out})
}

type driftBody struct {
	Observed []struct {
		Method string `json:"method"`
		Path   string `json:"path"`
	} `json:"observed"`
}

// DriftAPIBASInventory compares a target's inventory with routes the caller observed in use (from a gateway log, say). It reads
// the stored inventory and the request body only; it requests nothing from the target.
func (h *Handler) DriftAPIBASInventory(w http.ResponseWriter, r *http.Request) {
	var b driftBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if len(b.Observed) == 0 || len(b.Observed) > maxObservedRoute {
		jsonError(w, "observed must hold between 1 and 20000 routes", http.StatusBadRequest)
		return
	}
	obs := make([]openapi.Observed, 0, len(b.Observed))
	for _, o := range b.Observed {
		if !observedMethod.MatchString(o.Method) || len(o.Path) == 0 || len(o.Path) > 2048 || o.Path[0] != '/' {
			jsonError(w, "each observed route needs an upper-case method and a path starting with a slash", http.StatusBadRequest)
			return
		}
		obs = append(obs, openapi.Observed{Method: o.Method, Path: o.Path})
	}
	rec, inv, ok := h.loadInventory(w, r)
	if !ok {
		return
	}
	d := inv.Diff(obs)
	keys := func(ops []openapi.Operation) []string {
		out := make([]string, 0, len(ops))
		for _, o := range ops {
			out = append(out, o.Key())
		}
		return out
	}
	apibasRespond(w, http.StatusOK, map[string]any{
		"version":            rec.Version,
		"undocumented_total": len(d.Undocumented), "undocumented": capped(d.Undocumented, maxListedDrift),
		"unserved_total": len(d.Unserved), "unserved": capped(keys(d.Unserved), maxListedDrift),
		"deprecated_in_use": keys(d.DeprecatedInUse),
		"note":              "unserved means not seen in the observed routes, which is not proof the route is not served",
	})
}

// ListAPIBASTargets lists registered targets with their newest inventory version. It never returns credential references.
func (h *Handler) ListAPIBASTargets(w http.ResponseWriter, r *http.Request) {
	recs, err := db.ListAPIBASTargetSummaries(r.Context(), h.db)
	if err != nil {
		jsonError(w, "could not list targets", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(recs))
	for _, t := range recs {
		item := map[string]any{
			"id": t.ID, "name": t.Name, "base_url": t.BaseURL, "environment": t.Environment, "enabled": t.Enabled,
			"allowed_hosts": nonNilStrings(t.AllowedHosts), "allowed_paths": nonNilStrings(t.AllowedPaths),
			"scenario_count": t.ScenarioCount, "created_by": t.CreatedBy, "created_at": t.CreatedAt, "inventory": nil,
		}
		if t.InventoryVersion > 0 {
			item["inventory"] = map[string]any{"version": t.InventoryVersion, "operations": t.InventoryOps, "imported_at": t.InventoryAt}
		}
		out = append(out, item)
	}
	apibasRespond(w, http.StatusOK, map[string]any{"targets": out})
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
