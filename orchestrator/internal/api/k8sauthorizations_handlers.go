package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/k8sscenario"
)

// K8sAuthorizationRegistry is the storage the customer authorization handlers need. The database store satisfies it.
// Every change to a record is written together with its audit event, in one transaction.
type K8sAuthorizationRegistry interface {
	InsertWithAudit(ctx context.Context, a k8sscenario.CustomerAuthorization, ev k8sscenario.Event) error
	Get(ctx context.Context, id string) (k8sscenario.CustomerAuthorization, bool, error)
	List(ctx context.Context, clusterID string) ([]k8sscenario.CustomerAuthorization, error)
	RevokeWithAudit(ctx context.Context, id, revokedBy string, at time.Time, ev k8sscenario.Event) error
}

type k8sAuthorizationRequest struct {
	ClusterID   string    `json:"clusterId"`
	CustomerRef string    `json:"customerRef"`
	Scenarios   []string  `json:"scenarios"`
	Namespaces  []string  `json:"namespaces"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

// k8sAuthorizationView is what the API returns. State is computed at read time, so an expired record reads as expired.
type k8sAuthorizationView struct {
	ID           string     `json:"id"`
	ClusterID    string     `json:"clusterId"`
	CustomerRef  string     `json:"customerRef"`
	AuthorizedBy string     `json:"authorizedBy"`
	AuthorizedAt time.Time  `json:"authorizedAt"`
	ExpiresAt    time.Time  `json:"expiresAt"`
	Scenarios    []string   `json:"scenarios"`
	Namespaces   []string   `json:"namespaces"`
	State        string     `json:"state"`
	RevokedAt    *time.Time `json:"revokedAt,omitempty"`
	RevokedBy    string     `json:"revokedBy,omitempty"`
}

func toAuthorizationView(a k8sscenario.CustomerAuthorization, now time.Time) k8sAuthorizationView {
	return k8sAuthorizationView{ID: a.ID, ClusterID: a.ClusterID, CustomerRef: a.CustomerRef, AuthorizedBy: a.AuthorizedBy,
		AuthorizedAt: a.AuthorizedAt, ExpiresAt: a.ExpiresAt, Scenarios: a.Scenarios, Namespaces: a.Namespaces,
		State: k8sscenario.AuthorizationState(a, now), RevokedAt: a.RevokedAt, RevokedBy: a.RevokedBy}
}

// authorizationStoreReady reports whether the service can read and write authorization records.
func authorizationStoreReady(svc *K8sScenarioService) bool {
	return svc != nil && svc.Registry != nil && svc.Authorizations != nil
}

// CreateK8sAuthorization records a customer authorization for one cluster. Admin only.
// POST /api/k8s-scenarios/authorizations
func (h *Handler) CreateK8sAuthorization(w http.ResponseWriter, r *http.Request) {
	svc := h.k8sScenario
	if !authorizationStoreReady(svc) {
		jsonError(w, "Kubernetes scenarios are not configured", http.StatusServiceUnavailable)
		return
	}
	var body k8sAuthorizationRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	actor := actorID(r)
	if actor == "" {
		jsonError(w, "administrator identity is required", http.StatusUnauthorized)
		return
	}
	c, found, err := svc.Registry.Get(r.Context(), strings.TrimSpace(body.ClusterID))
	if err != nil {
		jsonError(w, "could not read the cluster", http.StatusInternalServerError)
		return
	}
	if !found {
		jsonError(w, "cluster not found", http.StatusNotFound)
		return
	}
	now := svc.now()
	a, err := k8sscenario.ValidateAuthorization(k8sscenario.AuthorizationRequest{
		ClusterID: c.ID, CustomerRef: body.CustomerRef, Scenarios: body.Scenarios,
		Namespaces: body.Namespaces, ExpiresAt: body.ExpiresAt,
	}, c.Class, actor, now)
	if errors.Is(err, k8sscenario.ErrAuthorizationClass) {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.ID = newK8sID("k8sa-")
	ev := k8sscenario.AuthorizationEvent("created", a, actor, c.DisplayName)
	switch err := svc.Authorizations.InsertWithAudit(r.Context(), a, ev); {
	case errors.Is(err, db.ErrCustomerNotFound):
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	case err != nil:
		// The transaction rolled back: nothing was stored, and no creation event exists either.
		jsonError(w, "authorization not created: the record and its audit event could not both be written", http.StatusInternalServerError)
		return
	}
	k8sJSON(w, http.StatusCreated, toAuthorizationView(a, now))
}

// ListK8sAuthorizations lists authorization records, optionally for one cluster. Admin only.
// GET /api/k8s-scenarios/authorizations?clusterId=
func (h *Handler) ListK8sAuthorizations(w http.ResponseWriter, r *http.Request) {
	svc := h.k8sScenario
	if !authorizationStoreReady(svc) {
		jsonError(w, "Kubernetes scenarios are not configured", http.StatusServiceUnavailable)
		return
	}
	records, err := svc.Authorizations.List(r.Context(), strings.TrimSpace(r.URL.Query().Get("clusterId")))
	if err != nil {
		jsonError(w, "could not list authorizations", http.StatusInternalServerError)
		return
	}
	now := svc.now()
	out := make([]k8sAuthorizationView, 0, len(records))
	for _, a := range records {
		out = append(out, toAuthorizationView(a, now))
	}
	k8sJSON(w, http.StatusOK, out)
}

// GetK8sAuthorization returns one authorization record. Admin only.
// GET /api/k8s-scenarios/authorizations/{id}
func (h *Handler) GetK8sAuthorization(w http.ResponseWriter, r *http.Request) {
	svc := h.k8sScenario
	if !authorizationStoreReady(svc) {
		jsonError(w, "Kubernetes scenarios are not configured", http.StatusServiceUnavailable)
		return
	}
	a, found, err := svc.Authorizations.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "could not read the authorization", http.StatusInternalServerError)
		return
	}
	if !found {
		jsonError(w, "authorization not found", http.StatusNotFound)
		return
	}
	k8sJSON(w, http.StatusOK, toAuthorizationView(a, svc.now()))
}

// RevokeK8sAuthorization revokes a record. Revocation takes effect immediately for every later plan and execute.
// Admin only. POST /api/k8s-scenarios/authorizations/{id}/revoke
func (h *Handler) RevokeK8sAuthorization(w http.ResponseWriter, r *http.Request) {
	svc := h.k8sScenario
	if !authorizationStoreReady(svc) {
		jsonError(w, "Kubernetes scenarios are not configured", http.StatusServiceUnavailable)
		return
	}
	actor := actorID(r)
	if actor == "" {
		jsonError(w, "administrator identity is required", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	a, found, err := svc.Authorizations.Get(r.Context(), id)
	if err != nil {
		jsonError(w, "could not read the authorization", http.StatusInternalServerError)
		return
	}
	if !found {
		jsonError(w, "authorization not found", http.StatusNotFound)
		return
	}
	now := svc.now()
	clusterName := ""
	if c, ok, err := svc.Registry.Get(r.Context(), a.ClusterID); err != nil {
		jsonError(w, "could not read the cluster", http.StatusInternalServerError)
		return
	} else if ok {
		clusterName = c.DisplayName
	}
	revoked := a
	revoked.RevokedAt = &now
	revoked.RevokedBy = actor
	ev := k8sscenario.AuthorizationEvent("revoked", revoked, actor, clusterName)
	if err := svc.Authorizations.RevokeWithAudit(r.Context(), id, actor, now, ev); err != nil {
		switch {
		case errors.Is(err, db.ErrAuthorizationNotFound):
			jsonError(w, "authorization not found", http.StatusNotFound)
		case errors.Is(err, db.ErrAuthorizationRevoked):
			jsonError(w, err.Error(), http.StatusConflict)
		default:
			jsonError(w, "authorization not revoked: the change and its audit event could not both be written", http.StatusInternalServerError)
		}
		return
	}
	a = revoked
	k8sJSON(w, http.StatusOK, toAuthorizationView(a, now))
}

// authorizeControlled is the server-side check for Controlled work. For any profile other than controlled it does
// nothing. For controlled it requires an active record where the cluster ID, the action ID and the namespace all match
// exactly, and returns that record so the caller can bind the run to it. A missing store, no match, or a read error
// denies. A denial returns 403 and writes a k8s.authorization.denied audit event; denied is then true.
func authorizeControlled(w http.ResponseWriter, r *http.Request, svc *K8sScenarioService,
	c k8sscenario.ClusterRecord, profile, action, namespace string) (k8sscenario.CustomerAuthorization, bool) {
	if profile != k8sscenario.ProfileControlled {
		return k8sscenario.CustomerAuthorization{}, false
	}
	deny := func(msg string, status int) (k8sscenario.CustomerAuthorization, bool) {
		if svc != nil && svc.Audit != nil {
			ev := k8sscenario.AuthorizationDenialEvent(action, c.ID, c.DisplayName, action, namespace, actorID(r))
			_ = svc.Audit.Write(r.Context(), ev)
		}
		jsonError(w, msg, status)
		return k8sscenario.CustomerAuthorization{}, true
	}
	if svc == nil || svc.Authorizations == nil {
		return deny("no customer authorization store is configured; Controlled work is denied", http.StatusForbidden)
	}
	records, err := svc.Authorizations.List(r.Context(), c.ID)
	if err != nil {
		jsonError(w, "could not read customer authorizations", http.StatusInternalServerError)
		return k8sscenario.CustomerAuthorization{}, true
	}
	rec, err := k8sscenario.MatchCustomerAuthorization(records, c.ID, action, namespace, svc.now())
	if err != nil {
		return deny(err.Error(), http.StatusForbidden)
	}
	return rec, false
}

// enforceCustomerAuthorization reports whether Controlled work is denied. See authorizeControlled.
func enforceCustomerAuthorization(w http.ResponseWriter, r *http.Request, svc *K8sScenarioService,
	c k8sscenario.ClusterRecord, profile, action, namespace string) bool {
	_, denied := authorizeControlled(w, r, svc, c, profile, action, namespace)
	return denied
}
