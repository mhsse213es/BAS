package cloudgraph

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// k8sBoundaryFileMax bounds how many expectations one file may hold, so the evaluation cost is bounded.
const k8sBoundaryFileMax = 500

// The expectations file is reviewed like other scenario content. It is read once at startup. Unknown keys are
// rejected, so a misspelt field cannot silently drop an expectation.
//
//	boundaries:
//	  - name: web-to-db-5432
//	    from: {namespace: np-app, labels: {app: web}}     # or: from: {external: true}
//	    to:   {namespace: np-db,  labels: {app: db}}
//	    port: 5432
//	    protocol: TCP        # optional, default TCP
//	    expect: allow        # or: block
type k8sBoundaryFile struct {
	Boundaries []k8sBoundaryEntry `yaml:"boundaries"`
}

type k8sBoundaryEntry struct {
	Name     string           `yaml:"name"`
	From     k8sEndpointEntry `yaml:"from"`
	To       k8sEndpointEntry `yaml:"to"`
	Port     int              `yaml:"port"`
	Protocol string           `yaml:"protocol"`
	Expect   string           `yaml:"expect"`
}

type k8sEndpointEntry struct {
	External  bool              `yaml:"external"`
	Namespace string            `yaml:"namespace"`
	Labels    map[string]string `yaml:"labels"`
}

// LoadK8sBoundaries parses and validates an expectations file. Any error means nothing is evaluated.
func LoadK8sBoundaries(data []byte) ([]K8sBoundary, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f k8sBoundaryFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("network-policy expectations: %w", err)
	}
	if len(f.Boundaries) == 0 {
		return nil, errors.New("network-policy expectations: no boundaries are listed")
	}
	if len(f.Boundaries) > k8sBoundaryFileMax {
		return nil, fmt.Errorf("network-policy expectations: %d boundaries exceeds the limit of %d", len(f.Boundaries), k8sBoundaryFileMax)
	}
	seen := map[string]bool{}
	out := make([]K8sBoundary, 0, len(f.Boundaries))
	for i, e := range f.Boundaries {
		name := strings.TrimSpace(e.Name)
		if name == "" {
			return nil, fmt.Errorf("network-policy expectations: boundary %d has no name", i+1)
		}
		if seen[name] {
			return nil, fmt.Errorf("network-policy expectations: boundary name %q is used more than once", name)
		}
		seen[name] = true
		b := K8sBoundary{
			Name:     name,
			From:     K8sWorkloadSelector{External: e.From.External, Namespace: e.From.Namespace, PodLabels: e.From.Labels},
			To:       K8sWorkloadSelector{External: e.To.External, Namespace: e.To.Namespace, PodLabels: e.To.Labels},
			Port:     e.Port,
			Protocol: e.Protocol,
			Expect:   e.Expect,
		}
		if err := validateBoundary(b); err != nil {
			return nil, fmt.Errorf("network-policy expectations: boundary %q: %w", name, err)
		}
		out = append(out, b)
	}
	return out, nil
}
