package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/taxii"
)

func taxiiConfigToJSON(c taxii.ConnectorConfig) map[string]any {
	return map[string]any{
		"id": c.ID, "name": c.Name, "serverUrl": c.ServerURL, "apiRoot": c.APIRoot,
		"collectionId": c.CollectionID, "authType": c.AuthType, "username": c.Username,
		"hasPassword": c.Password != "", "hasClientCert": c.ClientCert != "", "hasClientKey": c.ClientKey != "",
		"insecureTls": c.InsecureTLS,
		"enabled":     c.Enabled, "lastPollAt": c.LastPollAt, "lastPollStatus": c.LastPollStatus,
		"lastPollSummary": c.LastPollSummary, "lastError": c.LastError,
		"createdAt": c.CreatedAt, "updatedAt": c.UpdatedAt,
	}
}

type taxiiConnectorBody struct {
	Name         string `json:"name"`
	ServerURL    string `json:"serverUrl"`
	APIRoot      string `json:"apiRoot"`
	CollectionID string `json:"collectionId"`
	AuthType     string `json:"authType"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	ClientCert   string `json:"clientCert"`
	ClientKey    string `json:"clientKey"`
	InsecureTLS  bool   `json:"insecureTls"`
	Enabled      bool   `json:"enabled"`
}

// GET /api/taxii/connectors
func (h *Handler) ListTAXIIConnectors(w http.ResponseWriter, r *http.Request) {
	if h.taxiiStore == nil {
		jsonOK(w, []map[string]any{})
		return
	}
	cfgs, err := h.taxiiStore.List(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(cfgs))
	for _, c := range cfgs {
		out = append(out, taxiiConfigToJSON(c))
	}
	jsonOK(w, out)
}

// GET /api/taxii/connectors/{id}
func (h *Handler) GetTAXIIConnector(w http.ResponseWriter, r *http.Request) {
	if h.taxiiStore == nil {
		jsonError(w, "TAXII connector store not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	c, err := h.taxiiStore.Get(r.Context(), id)
	if err != nil {
		jsonError(w, "connector not found", http.StatusNotFound)
		return
	}
	jsonOK(w, taxiiConfigToJSON(c))
}

// POST /api/taxii/connectors
func (h *Handler) CreateTAXIIConnector(w http.ResponseWriter, r *http.Request) {
	if h.taxiiStore == nil {
		jsonError(w, "TAXII connector store not loaded", http.StatusServiceUnavailable)
		return
	}
	var body taxiiConnectorBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if body.Name == "" || body.ServerURL == "" {
		jsonError(w, "name and serverUrl are required", http.StatusBadRequest)
		return
	}
	created, err := h.taxiiStore.Create(r.Context(), taxii.ConnectorConfig{
		Name: body.Name, ServerURL: body.ServerURL, APIRoot: body.APIRoot, CollectionID: body.CollectionID,
		AuthType: body.AuthType, Username: body.Username, Password: body.Password,
		ClientCert: body.ClientCert, ClientKey: body.ClientKey, InsecureTLS: body.InsecureTLS, Enabled: body.Enabled,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if h.taxiiManager != nil {
		if err := h.taxiiManager.Reconcile(r.Context()); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	h.auditLog(r, "taxii.connector.create", created.ID, map[string]any{"name": created.Name, "enabled": created.Enabled}, "ok")
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, taxiiConfigToJSON(created))
}

// PUT /api/taxii/connectors/{id}
func (h *Handler) UpdateTAXIIConnector(w http.ResponseWriter, r *http.Request) {
	if h.taxiiStore == nil {
		jsonError(w, "TAXII connector store not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	var body taxiiConnectorBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	updated, err := h.taxiiStore.Update(r.Context(), id, taxii.ConnectorConfig{
		Name: body.Name, ServerURL: body.ServerURL, APIRoot: body.APIRoot, CollectionID: body.CollectionID,
		AuthType: body.AuthType, Username: body.Username, Password: body.Password,
		ClientCert: body.ClientCert, ClientKey: body.ClientKey, InsecureTLS: body.InsecureTLS, Enabled: body.Enabled,
	}, body.Password == "", body.ClientCert == "", body.ClientKey == "")
	if err != nil {
		if err == taxii.ErrNotFound {
			jsonError(w, "connector not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if h.taxiiManager != nil {
		if err := h.taxiiManager.Reconcile(r.Context()); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	h.auditLog(r, "taxii.connector.update", id, map[string]any{"name": updated.Name, "enabled": updated.Enabled}, "ok")
	jsonOK(w, taxiiConfigToJSON(updated))
}

// DELETE /api/taxii/connectors/{id}
func (h *Handler) DeleteTAXIIConnector(w http.ResponseWriter, r *http.Request) {
	if h.taxiiStore == nil {
		jsonError(w, "TAXII connector store not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	if err := h.taxiiStore.Delete(r.Context(), id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if h.taxiiManager != nil {
		if err := h.taxiiManager.Reconcile(r.Context()); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	h.auditLog(r, "taxii.connector.delete", id, nil, "ok")
	jsonOK(w, map[string]string{"id": id, "status": "deleted"})
}

// POST /api/taxii/connectors/test — validates connectivity/credentials
// BEFORE a row is saved, mirroring TestThreatIntelConfig's existing
// precedent. Takes the full form body, not a saved connector id.
func (h *Handler) TestTAXIIConnector(w http.ResponseWriter, r *http.Request) {
	var body taxiiConnectorBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if body.ServerURL == "" {
		jsonError(w, "serverUrl is required", http.StatusBadRequest)
		return
	}
	client := taxii.NewClient(taxii.ConnectorConfig{
		ServerURL: body.ServerURL, AuthType: body.AuthType, Username: body.Username, Password: body.Password,
		InsecureTLS: body.InsecureTLS,
	})
	disc, err := client.Discover(r.Context())
	if err != nil {
		jsonOK(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	apiRoot := body.APIRoot
	if apiRoot == "" {
		apiRoot = disc.DefaultAPIRoot
	}
	collections, err := client.ListCollections(r.Context(), apiRoot)
	if err != nil {
		jsonOK(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	jsonOK(w, map[string]any{"ok": true, "collectionCount": len(collections)})
}

// POST /api/taxii/connectors/{id}/sync — manual trigger for one connector.
func (h *Handler) SyncTAXIIConnector(w http.ResponseWriter, r *http.Request) {
	if h.taxiiManager == nil {
		jsonError(w, "TAXII connector manager not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	if err := h.taxiiManager.TriggerSync(r.Context(), id); err != nil {
		jsonOK(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	h.auditLog(r, "taxii.connector.sync", id, nil, "ok")
	jsonOK(w, map[string]any{"ok": true})
}
