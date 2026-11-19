package cloudgraph

import (
	"context"
	"strings"
	"testing"
)

const validBoundaryFile = `
boundaries:
  - name: web-to-db-5432
    from: {namespace: np-app, labels: {app: web}}
    to:   {namespace: np-db, labels: {app: db}}
    port: 5432
    expect: allow
  - name: external-to-db
    from: {external: true}
    to:   {namespace: np-db, labels: {app: db}}
    port: 5432
    protocol: TCP
    expect: block
`

func TestLoadK8sBoundaries_ValidFile(t *testing.T) {
	bs, err := LoadK8sBoundaries([]byte(validBoundaryFile))
	if err != nil {
		t.Fatalf("valid file rejected: %v", err)
	}
	if len(bs) != 2 || bs[0].Name != "web-to-db-5432" || !bs[1].From.External {
		t.Fatalf("parsed wrong: %+v", bs)
	}
	if bs[0].From.PodLabels["app"] != "web" || bs[0].To.Namespace != "np-db" {
		t.Errorf("selectors not carried through: %+v", bs[0])
	}
}

// Each case must fail, and the message must name the boundary or the key at fault.
func TestLoadK8sBoundaries_RejectsInvalidFiles(t *testing.T) {
	cases := map[string]struct {
		body    string
		mention string
	}{
		"unknown key is not silently dropped": {
			"boundaries:\n  - name: a\n    from: {namespace: x}\n    to: {namespace: y}\n    port: 80\n    expcet: allow\n",
			"expcet",
		},
		"missing name": {
			"boundaries:\n  - from: {namespace: x}\n    to: {namespace: y}\n    port: 80\n    expect: allow\n",
			"has no name",
		},
		"duplicate name": {
			validBoundaryFile + "  - name: web-to-db-5432\n    from: {external: true}\n    to: {namespace: np-db}\n    port: 1\n    expect: block\n",
			"more than once",
		},
		"bad expect": {
			"boundaries:\n  - name: a\n    from: {namespace: x}\n    to: {namespace: y}\n    port: 80\n    expect: maybe\n",
			"expect must be",
		},
		"external destination": {
			"boundaries:\n  - name: a\n    from: {namespace: x}\n    to: {external: true}\n    port: 80\n    expect: allow\n",
			"destination cannot be external",
		},
		"port out of range": {
			"boundaries:\n  - name: a\n    from: {namespace: x}\n    to: {namespace: y}\n    port: 70000\n    expect: allow\n",
			"out of range",
		},
		"no boundaries": {
			"boundaries: []\n",
			"no boundaries",
		},
		"not yaml": {
			"boundaries: [unclosed",
			"network-policy expectations",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadK8sBoundaries([]byte(tc.body))
			if err == nil {
				t.Fatal("invalid file accepted")
			}
			if !strings.Contains(err.Error(), tc.mention) {
				t.Errorf("error %q does not mention %q", err, tc.mention)
			}
		})
	}
}

// The analysis report carries the expectations' results, and discovery itself is read-only.
func TestRunK8sAnalysisWith_AttachesBoundaryResults(t *testing.T) {
	srv, _ := newK8sTestServer(t, serveRoutes(map[string]string{
		netpolPath:           `{"items":[{"metadata":{"name":"default-deny","namespace":"default"},"spec":{"podSelector":{},"policyTypes":["Ingress"]}}]}`,
		"/api/v1/pods":       `{"items":[{"metadata":{"name":"web-1","namespace":"default","labels":{"app":"web"}},"spec":{"serviceAccountName":"web"}}]}`,
		"/api/v1/namespaces": `{"items":[{"metadata":{"name":"default","labels":{"name":"default"}}}]}`,
	}))
	bs, err := LoadK8sBoundaries([]byte(`
boundaries:
  - name: web-to-web-80
    from: {namespace: default, labels: {app: web}}
    to:   {namespace: default, labels: {app: web}}
    port: 80
    expect: block
`))
	if err != nil {
		t.Fatal(err)
	}
	cfg := K8sDiscoveryConfig{ClusterName: "kind-bas-lab", APIServer: srv.URL, Token: "test-token", CAPEM: k8sCAPEM(srv)}
	res, err := RunK8sAnalysisWith(context.Background(), cfg, bs)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.NetworkPolicy) != 1 {
		t.Fatalf("boundary results = %d, want 1", len(res.NetworkPolicy))
	}
	got := res.NetworkPolicy[0]
	if got.Name != "web-to-web-80" || got.Configured != NetpolConfiguredBlocks || !got.Matches {
		t.Errorf("result = %+v, want the default-deny to block and match expect block", got)
	}
}

// With no expectations file the report still carries an empty list, not null.
func TestRunK8sAnalysisWith_NoExpectationsIsEmptyNotNull(t *testing.T) {
	srv, _ := newK8sTestServer(t, serveRoutes(nil))
	cfg := K8sDiscoveryConfig{ClusterName: "kind-bas-lab", APIServer: srv.URL, Token: "test-token", CAPEM: k8sCAPEM(srv)}
	res, err := RunK8sAnalysisWith(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.NetworkPolicy == nil || len(res.NetworkPolicy) != 0 {
		t.Errorf("NetworkPolicy = %#v, want an empty slice", res.NetworkPolicy)
	}
}
