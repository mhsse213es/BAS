package cloudgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

// k8sNamespaceItem is the part of a Namespace object the listing needs.
type k8sNamespaceItem struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
}

// ListNamespaces returns the sorted names of the cluster's namespaces. It is read-only: one list call on
// /api/v1/namespaces through the same client that discovery uses. A 401 is returned as ErrK8sUnauthorized.
func (c *K8sDiscoveryClient) ListNamespaces(ctx context.Context) ([]string, error) {
	items, gap, err := c.list(ctx, "/api/v1/namespaces")
	if err != nil {
		return nil, err
	}
	if gap != "" {
		return nil, fmt.Errorf("kubernetes namespaces: %s", gap)
	}
	out := make([]string, 0, len(items))
	for _, raw := range items {
		var ns k8sNamespaceItem
		if err := json.Unmarshal(raw, &ns); err != nil {
			return nil, fmt.Errorf("kubernetes namespaces: malformed item: %w", err)
		}
		if ns.Metadata.Name != "" {
			out = append(out, ns.Metadata.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}
