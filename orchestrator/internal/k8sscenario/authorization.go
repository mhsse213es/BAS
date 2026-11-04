package k8sscenario

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// ProfileControlled is the execution profile for state-changing actions on a customer's non-production cluster.
const ProfileControlled = "controlled"

// ProfileLab is the profile for lab-only actions.
const ProfileLab = "lab"

// controlledActions lists the actions that run under the Controlled profile. It is empty: Controlled execution stays
// disabled until the execution lifecycle (identity binding, kill switch, cancellation, timeout, audit) is proven. The
// ConfigMap patch is the first candidate, enabled by a separate decision once that is done.
var controlledActions = map[string]bool{}

// ActionProfile returns the execution profile an action runs under.
func ActionProfile(actionID string) string {
	if controlledActions[actionID] {
		return ProfileControlled
	}
	return ProfileLab
}

// MaxAuthorizationTerm is the longest a customer authorization may run. A renewal is a new record.
const MaxAuthorizationTerm = 90 * 24 * time.Hour

const (
	maxAuthorizationScenarios  = 16
	maxAuthorizationNamespaces = 32
	maxCustomerRefLength       = 128
)

var (
	// ErrAuthorizationDenied means no active authorization covers this cluster, scenario and namespace.
	ErrAuthorizationDenied = errors.New("no active customer authorization covers this cluster, scenario and namespace")
	// ErrAuthorizationClass means the cluster's class does not allow the Controlled profile at all.
	ErrAuthorizationClass = errors.New("the cluster's class does not allow the Controlled profile")

	reAuthNamespace   = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	reCustomerRefBody = regexp.MustCompile(`^[^\x00-\x1f\x7f]+$`)
)

// CustomerAuthorization is the per-cluster permission a customer grants for Controlled work. It is separate from the
// per-run approval, which still has to be given for each exact run. Both are required.
type CustomerAuthorization struct {
	ID          string
	ClusterID   string
	CustomerRef string
	// AuthorizedBy is the administrator who created the record. The run approver is recorded on the run, not here.
	AuthorizedBy string
	AuthorizedAt time.Time
	ExpiresAt    time.Time
	Scenarios    []string
	Namespaces   []string
	RevokedAt    *time.Time
	RevokedBy    string
}

// AuthorizationRequest is what an administrator submits. Every field is explicit: there are no wildcards.
type AuthorizationRequest struct {
	ClusterID   string
	CustomerRef string
	Scenarios   []string
	Namespaces  []string
	ExpiresAt   time.Time
}

// ValidateAuthorization checks a request against the cluster's class, the action catalogue and the time limit. It
// returns the record to store, with AuthorizedAt set to now. Empty lists, wildcards and duplicates are refused.
func ValidateAuthorization(req AuthorizationRequest, clusterClass, authorizedBy string, now time.Time) (CustomerAuthorization, error) {
	if !slices.Contains(AllowedProfiles(clusterClass), ProfileControlled) {
		return CustomerAuthorization{}, ErrAuthorizationClass
	}
	clusterID := strings.TrimSpace(req.ClusterID)
	if clusterID == "" {
		return CustomerAuthorization{}, errors.New("clusterId is required")
	}
	customer := strings.TrimSpace(req.CustomerRef)
	if customer == "" || len(customer) > maxCustomerRefLength || !reCustomerRefBody.MatchString(customer) {
		return CustomerAuthorization{}, fmt.Errorf("customerRef is required, at most %d characters, with no control characters", maxCustomerRefLength)
	}
	scenarios, err := normaliseList(req.Scenarios, maxAuthorizationScenarios, "scenarios", func(s string) error {
		if _, ok := Registry()[s]; !ok {
			return fmt.Errorf("scenario %q is not in the action catalogue", s)
		}
		return nil
	})
	if err != nil {
		return CustomerAuthorization{}, err
	}
	namespaces, err := normaliseList(req.Namespaces, maxAuthorizationNamespaces, "namespaces", func(ns string) error {
		if !reAuthNamespace.MatchString(ns) {
			return fmt.Errorf("namespace %q is not a valid Kubernetes namespace name", ns)
		}
		return nil
	})
	if err != nil {
		return CustomerAuthorization{}, err
	}
	if !req.ExpiresAt.After(now) {
		return CustomerAuthorization{}, errors.New("expiresAt must be in the future")
	}
	if req.ExpiresAt.After(now.Add(MaxAuthorizationTerm)) {
		return CustomerAuthorization{}, fmt.Errorf("expiresAt may be at most %d days ahead", int(MaxAuthorizationTerm.Hours()/24))
	}
	return CustomerAuthorization{
		ClusterID: clusterID, CustomerRef: customer, AuthorizedBy: authorizedBy,
		AuthorizedAt: now.UTC().Truncate(time.Second), ExpiresAt: req.ExpiresAt.UTC().Truncate(time.Second),
		Scenarios: scenarios, Namespaces: namespaces,
	}, nil
}

// normaliseList trims each entry, refuses blanks, wildcards, duplicates, too many entries, and anything check rejects.
// An empty list is refused: an empty allowlist means nothing is allowed.
func normaliseList(in []string, max int, field string, check func(string) error) ([]string, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("%s must list at least one entry; an empty list denies everything", field)
	}
	if len(in) > max {
		return nil, fmt.Errorf("%s may list at most %d entries", field, max)
	}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			return nil, fmt.Errorf("%s must not contain blank entries", field)
		}
		if v == "*" || strings.Contains(v, "*") {
			return nil, fmt.Errorf("%s must name each entry explicitly; wildcards are not allowed", field)
		}
		if slices.Contains(out, v) {
			return nil, fmt.Errorf("%s lists %q twice", field, v)
		}
		if err := check(v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// AuthorizationState describes a record at a point in time.
func AuthorizationState(a CustomerAuthorization, now time.Time) string {
	switch {
	case a.RevokedAt != nil:
		return "revoked"
	case !now.Before(a.ExpiresAt):
		return "expired"
	}
	return "active"
}

// CheckCustomerAuthorization returns nil only when some record for this exact cluster is active (not revoked, not
// expired) and names this exact scenario and this exact namespace. Anything else is denied, including an empty record.
func CheckCustomerAuthorization(records []CustomerAuthorization, clusterID, scenario, namespace string, now time.Time) error {
	if clusterID == "" || scenario == "" || namespace == "" {
		return ErrAuthorizationDenied
	}
	for _, a := range records {
		if a.ClusterID != clusterID || AuthorizationState(a, now) != "active" {
			continue
		}
		if len(a.Scenarios) == 0 || len(a.Namespaces) == 0 {
			continue
		}
		if slices.Contains(a.Scenarios, scenario) && slices.Contains(a.Namespaces, namespace) {
			return nil
		}
	}
	return ErrAuthorizationDenied
}

// AuthorizationEvent is the audit record for an authorization lifecycle change: created, revoked, or denied at
// enforcement. The customer and cluster identifiers are always included.
func AuthorizationEvent(kind string, a CustomerAuthorization, actor, clusterName string) Event {
	return Event{
		Type:  "k8s.authorization." + kind,
		RunID: a.ID,
		Fields: map[string]string{
			"requester":       actor,
			"authorizationId": a.ID,
			"clusterId":       a.ClusterID,
			"cluster":         clusterName,
			"customerRef":     a.CustomerRef,
			"authorizedBy":    a.AuthorizedBy,
			"scenarios":       strings.Join(a.Scenarios, ","),
			"namespaces":      strings.Join(a.Namespaces, ","),
			"expiresAt":       a.ExpiresAt.UTC().Format(time.RFC3339),
		},
	}
}

// AuthorizationDenialEvent records a Controlled request that no active authorization covered.
func AuthorizationDenialEvent(action, clusterID, clusterName, scenario, namespace, actor string) Event {
	return Event{
		Type:  "k8s.authorization.denied",
		RunID: action,
		Fields: map[string]string{
			"requester": actor,
			"clusterId": clusterID,
			"cluster":   clusterName,
			"scenario":  scenario,
			"namespace": namespace,
			"reason":    ErrAuthorizationDenied.Error(),
		},
	}
}
