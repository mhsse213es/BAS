package main

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/k8sscenario"
)

func TestResolveConfiguredCluster_RequiresRegisteredLabAtSameServer(t *testing.T) {
	lab := k8sscenario.ClusterRecord{ID: "k8sc-1", DisplayName: "kind-bas-lab",
		ServerURL: "https://127.0.0.1:61567", Class: k8sscenario.ClassLab}
	prod := k8sscenario.ClusterRecord{ID: "k8sc-2", DisplayName: "prod-east",
		ServerURL: "https://prod.example:6443", Class: k8sscenario.ClassProduction}
	registered := []k8sscenario.ClusterRecord{lab, prod}

	if rec, err := resolveConfiguredCluster(registered, "kind-bas-lab", "https://127.0.0.1:61567/"); err != nil || rec.ID != "k8sc-1" {
		t.Errorf("a registered lab cluster at the same server must resolve: %+v %v", rec, err)
	}
	cases := map[string]struct {
		name, server string
		list         []k8sscenario.ClusterRecord
		want         string
	}{
		"not registered":          {"kind-bas-lab", "https://127.0.0.1:61567", nil, "not registered"},
		"production class":        {"prod-east", "https://prod.example:6443", registered, "needs class"},
		"different server":        {"kind-bas-lab", "https://10.0.0.1:6443", registered, "does not match"},
		"plain http server":       {"kind-bas-lab", "http://127.0.0.1:61567", registered, "must use https"},
		"name not in list at all": {"ghost", "https://127.0.0.1:61567", registered, "not registered"},
	}
	for name, c := range cases {
		_, err := resolveConfiguredCluster(c.list, c.name, c.server)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want error containing %q, got %v", name, c.want, err)
		}
	}
}
