package k8sscenario

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var authNow = time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)

func goodRequest() AuthorizationRequest {
	return AuthorizationRequest{ClusterID: "k8sc-1", CustomerRef: "customer-acme",
		Scenarios: []string{"configmap-patch-labelled"}, Namespaces: []string{"bas-sandbox"},
		ExpiresAt: authNow.Add(30 * 24 * time.Hour)}
}

func TestValidateAuthorization_AcceptsAnExplicitRequest(t *testing.T) {
	a, err := ValidateAuthorization(goodRequest(), ClassNonProduction, "admin-1", authNow)
	if err != nil {
		t.Fatalf("a valid request must be accepted: %v", err)
	}
	if a.AuthorizedBy != "admin-1" || !a.AuthorizedAt.Equal(authNow) || a.ClusterID != "k8sc-1" {
		t.Errorf("record fields wrong: %+v", a)
	}
}

func TestValidateAuthorization_RefusesWhatIsNotExplicit(t *testing.T) {
	cases := map[string]struct {
		mutate func(*AuthorizationRequest)
		class  string
		want   string
	}{
		"empty scenario list":   {func(r *AuthorizationRequest) { r.Scenarios = nil }, ClassNonProduction, "at least one"},
		"empty namespace list":  {func(r *AuthorizationRequest) { r.Namespaces = nil }, ClassNonProduction, "at least one"},
		"wildcard scenario":     {func(r *AuthorizationRequest) { r.Scenarios = []string{"*"} }, ClassNonProduction, "wildcard"},
		"wildcard namespace":    {func(r *AuthorizationRequest) { r.Namespaces = []string{"bas-*"} }, ClassNonProduction, "wildcard"},
		"unknown scenario":      {func(r *AuthorizationRequest) { r.Scenarios = []string{"made-up"} }, ClassNonProduction, "not in the action catalogue"},
		"bad namespace name":    {func(r *AuthorizationRequest) { r.Namespaces = []string{"Bas_Sandbox"} }, ClassNonProduction, "not a valid"},
		"duplicate namespace":   {func(r *AuthorizationRequest) { r.Namespaces = []string{"a-ns", "a-ns"} }, ClassNonProduction, "twice"},
		"blank namespace":       {func(r *AuthorizationRequest) { r.Namespaces = []string{"  "} }, ClassNonProduction, "blank"},
		"blank customer":        {func(r *AuthorizationRequest) { r.CustomerRef = " " }, ClassNonProduction, "customerRef"},
		"expiry in the past":    {func(r *AuthorizationRequest) { r.ExpiresAt = authNow.Add(-time.Minute) }, ClassNonProduction, "future"},
		"expiry beyond 90 days": {func(r *AuthorizationRequest) { r.ExpiresAt = authNow.Add(MaxAuthorizationTerm + time.Hour) }, ClassNonProduction, "at most"},
		"missing cluster":       {func(r *AuthorizationRequest) { r.ClusterID = "" }, ClassNonProduction, "clusterId"},
	}
	for name, c := range cases {
		req := goodRequest()
		c.mutate(&req)
		_, err := ValidateAuthorization(req, c.class, "admin-1", authNow)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want error containing %q, got %v", name, c.want, err)
		}
	}
}

func TestValidateAuthorization_ProductionClusterCannotBeAuthorised(t *testing.T) {
	_, err := ValidateAuthorization(goodRequest(), ClassProduction, "admin-1", authNow)
	if !errors.Is(err, ErrAuthorizationClass) {
		t.Errorf("a production cluster must be refused for Controlled authorization, got %v", err)
	}
}

func activeRecord() CustomerAuthorization {
	return CustomerAuthorization{ID: "k8sa-1", ClusterID: "k8sc-1", Scenarios: []string{"configmap-patch-labelled"},
		Namespaces: []string{"bas-sandbox"}, AuthorizedAt: authNow, ExpiresAt: authNow.Add(time.Hour)}
}

func TestCheckCustomerAuthorization_MatchesExactlyOrDenies(t *testing.T) {
	rec := []CustomerAuthorization{activeRecord()}
	if err := CheckCustomerAuthorization(rec, "k8sc-1", "configmap-patch-labelled", "bas-sandbox", authNow); err != nil {
		t.Fatalf("an exact active match must be allowed: %v", err)
	}
	denied := map[string]struct {
		records   []CustomerAuthorization
		cluster   string
		scenario  string
		namespace string
		now       time.Time
	}{
		"other cluster":        {rec, "k8sc-2", "configmap-patch-labelled", "bas-sandbox", authNow},
		"other scenario":       {rec, "k8sc-1", "sa-token-probe", "bas-sandbox", authNow},
		"other namespace":      {rec, "k8sc-1", "configmap-patch-labelled", "kube-system", authNow},
		"namespace prefix":     {rec, "k8sc-1", "configmap-patch-labelled", "bas-sand", authNow},
		"no records":           {nil, "k8sc-1", "configmap-patch-labelled", "bas-sandbox", authNow},
		"empty scenario list":  {[]CustomerAuthorization{{ClusterID: "k8sc-1", Namespaces: []string{"bas-sandbox"}, ExpiresAt: authNow.Add(time.Hour)}}, "k8sc-1", "configmap-patch-labelled", "bas-sandbox", authNow},
		"empty namespace list": {[]CustomerAuthorization{{ClusterID: "k8sc-1", Scenarios: []string{"configmap-patch-labelled"}, ExpiresAt: authNow.Add(time.Hour)}}, "k8sc-1", "configmap-patch-labelled", "bas-sandbox", authNow},
		"expired exactly now":  {rec, "k8sc-1", "configmap-patch-labelled", "bas-sandbox", authNow.Add(time.Hour)},
		"blank cluster":        {rec, "", "configmap-patch-labelled", "bas-sandbox", authNow},
		"blank namespace":      {rec, "k8sc-1", "configmap-patch-labelled", "", authNow},
	}
	for name, c := range denied {
		if err := CheckCustomerAuthorization(c.records, c.cluster, c.scenario, c.namespace, c.now); !errors.Is(err, ErrAuthorizationDenied) {
			t.Errorf("%s: must be denied, got %v", name, err)
		}
	}
}

func TestCheckCustomerAuthorization_RevokedRecordDenies(t *testing.T) {
	r := activeRecord()
	revoked := authNow.Add(time.Minute)
	r.RevokedAt = &revoked
	if err := CheckCustomerAuthorization([]CustomerAuthorization{r}, "k8sc-1", "configmap-patch-labelled", "bas-sandbox", authNow.Add(2*time.Minute)); !errors.Is(err, ErrAuthorizationDenied) {
		t.Errorf("a revoked record must deny, got %v", err)
	}
}

func TestCheckCustomerAuthorization_OneGoodRecordIsEnoughEvenWithBadOnes(t *testing.T) {
	bad := activeRecord()
	bad.Namespaces = []string{"kube-system"}
	good := activeRecord()
	good.ID = "k8sa-2"
	if err := CheckCustomerAuthorization([]CustomerAuthorization{bad, good}, "k8sc-1", "configmap-patch-labelled", "bas-sandbox", authNow); err != nil {
		t.Errorf("a matching active record must allow even when other records do not match: %v", err)
	}
}

func TestAuthorizationState(t *testing.T) {
	r := activeRecord()
	if AuthorizationState(r, authNow) != "active" {
		t.Error("a fresh record must be active")
	}
	if AuthorizationState(r, authNow.Add(time.Hour)) != "expired" {
		t.Error("a record past its expiry must read as expired")
	}
	rev := authNow
	r.RevokedAt = &rev
	if AuthorizationState(r, authNow) != "revoked" {
		t.Error("a revoked record must read as revoked")
	}
}

// Controlled execution stays disabled: no action is classified Controlled.
func TestActionProfile_NoActionIsControlled(t *testing.T) {
	for id := range Registry() {
		if ActionProfile(id) != ProfileLab {
			t.Errorf("action %s is classified %s; Controlled must stay disabled", id, ActionProfile(id))
		}
	}
}

func TestAuthorizationEvent_CarriesCustomerAndCluster(t *testing.T) {
	rec := activeRecord()
	rec.CustomerRef = "customer-acme"
	ev := AuthorizationEvent("created", rec, "admin-1", "kind-bas-lab")
	if ev.Type != "k8s.authorization.created" || ev.Fields["customerRef"] != "customer-acme" {
		t.Errorf("event type or customer field wrong: %+v", ev)
	}
	if ev.Fields["clusterId"] != "k8sc-1" || ev.Fields["cluster"] != "kind-bas-lab" || ev.Fields["requester"] != "admin-1" {
		t.Errorf("event must carry the cluster and the actor: %+v", ev.Fields)
	}
}
