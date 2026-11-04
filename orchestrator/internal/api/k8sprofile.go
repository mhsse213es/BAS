package api

import (
	"context"
	"net/http"

	"github.com/audspect/bas/internal/k8sscenario"
)

// refuseProfile enforces the execution profile for a request against a registered cluster. When the cluster's class
// does not allow the profile, it writes a 403, records the refusal in the audit log, and returns true. The refusal
// happens whether or not the audit write succeeds; a failed write is logged, not hidden.
func refuseProfile(w http.ResponseWriter, r *http.Request, svc *K8sScenarioService, c k8sscenario.ClusterRecord, profile, action string) bool {
	if err := k8sscenario.EnforceProfile(c.Class, profile); err == nil {
		return false
	}
	if svc != nil && svc.Audit != nil {
		ev := k8sscenario.RefusalEvent(action, c.ID, c.DisplayName, c.Class, profile, actorID(r))
		if err := svc.Audit.Write(r.Context(), ev); err != nil {
			jsonError(w, "profile refused and the refusal could not be recorded", http.StatusInternalServerError)
			return true
		}
	}
	jsonError(w, "this cluster's class does not allow the "+profile+" profile", http.StatusForbidden)
	return true
}

// clusterByDisplayName finds a registered cluster by its display name. Runs store the name, so execution uses this.
func clusterByDisplayName(ctx context.Context, svc *K8sScenarioService, name string) (k8sscenario.ClusterRecord, bool, error) {
	if svc == nil || svc.Registry == nil {
		return k8sscenario.ClusterRecord{}, false, nil
	}
	list, err := svc.Registry.List(ctx)
	if err != nil {
		return k8sscenario.ClusterRecord{}, false, err
	}
	for _, c := range list {
		if c.DisplayName == name {
			return c, true, nil
		}
	}
	return k8sscenario.ClusterRecord{}, false, nil
}
