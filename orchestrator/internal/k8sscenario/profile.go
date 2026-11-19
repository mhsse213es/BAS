package k8sscenario

import (
	"errors"
	"fmt"
)

// ErrProfileRefused is returned when a cluster's class does not allow the requested execution profile.
var ErrProfileRefused = errors.New("execution profile not allowed for this cluster class")

// EnforceProfile is the backend check for an execution profile (docs/k8s-bas/SPEC-first-wave.md section 2). It is the
// one rule every Kubernetes run path uses: a request for a profile the cluster's registered class does not allow is
// refused before any credential is read or any request is sent.
func EnforceProfile(class, profile string) error {
	for _, p := range AllowedProfiles(class) {
		if p == profile {
			return nil
		}
	}
	return fmt.Errorf("%w: class %q does not allow profile %q", ErrProfileRefused, class, profile)
}

// RefusalEvent is the audit record for a refused profile request. The check or action that was asked for, the cluster,
// its class, the profile and the requester are recorded, so a refusal can be traced.
func RefusalEvent(action, clusterID, clusterName, class, profile, requester string) Event {
	return Event{
		Type:  "k8s.profile.refused",
		RunID: action,
		Fields: map[string]string{
			"requester": requester,
			"action":    action,
			"clusterId": clusterID,
			"cluster":   clusterName,
			"class":     class,
			"profile":   profile,
			"reason":    "profile not allowed for cluster class",
		},
	}
}
