package cloudgraph

import (
	"testing"
)

const tokenPodsFixture = `{"items":[` +
	`{"metadata":{"name":"mounted","namespace":"default"},"spec":{"serviceAccountName":"web"}},` +
	`{"metadata":{"name":"unneeded","namespace":"default"},"spec":{"serviceAccountName":"idle"}},` +
	`{"metadata":{"name":"optout","namespace":"default"},"spec":{"serviceAccountName":"quiet"}},` +
	`{"metadata":{"name":"podoptout","namespace":"default"},"spec":{"serviceAccountName":"web","automountServiceAccountToken":false}}` +
	`]}`

const tokenSAsFixture = `{"items":[` +
	`{"metadata":{"name":"web","namespace":"default"}},` +
	`{"metadata":{"name":"idle","namespace":"default"}},` +
	`{"metadata":{"name":"quiet","namespace":"default"},"automountServiceAccountToken":false}` +
	`]}`

func tokenFindingFor(got []K8sTokenExposureFinding, workload string) (K8sTokenExposureFinding, bool) {
	for _, f := range got {
		if f.Workload == "k8s://kind-bas-lab/default/pod/"+workload {
			return f, true
		}
	}
	return K8sTokenExposureFinding{}, false
}

// TestTokenExposure_MountedAndUsedIsReportedButNotUnneeded checks a mounted token whose account has bindings is
// reported as mounted, and not as unneeded.
func TestTokenExposure_MountedAndUsedIsReportedButNotUnneeded(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{"/api/v1/pods": tokenPodsFixture, "/api/v1/serviceaccounts": tokenSAsFixture})
	f, ok := tokenFindingFor(K8sTokenExposureFindings(inv, rep), "mounted")
	if !ok || f.Unneeded || len(f.Bindings) == 0 {
		t.Fatalf("mounted finding = %+v (found %v), want reported with bindings and not unneeded", f, ok)
	}
}

// TestTokenExposure_MountedWithNoBindingsIsUnneeded checks a mounted token whose account has no bindings is
// reported as unneeded.
func TestTokenExposure_MountedWithNoBindingsIsUnneeded(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{"/api/v1/pods": tokenPodsFixture, "/api/v1/serviceaccounts": tokenSAsFixture})
	f, ok := tokenFindingFor(K8sTokenExposureFindings(inv, rep), "unneeded")
	if !ok || !f.Unneeded || len(f.Bindings) != 0 {
		t.Fatalf("unneeded finding = %+v (found %v), want reported as unneeded", f, ok)
	}
}

// TestTokenExposure_OptOutOnServiceAccountIsRespected checks an account that opts out of token mounting is not
// reported when the pod does not set its own value.
func TestTokenExposure_OptOutOnServiceAccountIsRespected(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{"/api/v1/pods": tokenPodsFixture, "/api/v1/serviceaccounts": tokenSAsFixture})
	if _, ok := tokenFindingFor(K8sTokenExposureFindings(inv, rep), "optout"); ok {
		t.Fatal("a pod whose account opts out of token mounting must not be reported")
	}
}

// TestTokenExposure_PodOptOutOverridesAccount checks a pod that opts out is not reported, even though its account
// would otherwise mount the token.
func TestTokenExposure_PodOptOutOverridesAccount(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{"/api/v1/pods": tokenPodsFixture, "/api/v1/serviceaccounts": tokenSAsFixture})
	if _, ok := tokenFindingFor(K8sTokenExposureFindings(inv, rep), "podoptout"); ok {
		t.Fatal("a pod that sets automountServiceAccountToken=false must not be reported")
	}
}
