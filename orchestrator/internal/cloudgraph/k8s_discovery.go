package cloudgraph

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Kubernetes discovery (Phase 1: read-only). It lists namespaces, pods, service accounts, Roles,
// ClusterRoles, RoleBindings and ClusterRoleBindings, and writes them into the shared cloud graph.
//
// Safety boundary: the client issues only GET requests. Nothing here creates, patches, deletes or
// execs anything in the cluster. Every list that cannot be read in full is reported as a gap, and a
// report with any gap is never Complete, so an incomplete inventory is never presented as full coverage.
//
// Kubernetes RBAC is kept in its own terms. A binding is recorded as a permission edge from a subject
// to a role, with the role's rules kept as attributes. No verb or resource evaluation happens here,
// and the result is not mapped onto AWS IAM or Azure RBAC semantics.

const (
	k8sSource         = "kubernetes-api"
	k8sMaxBody        = 32 << 20
	k8sDefaultPage    = 500
	k8sDefaultMaxPage = 200
	k8sClusterNS      = "_cluster"
)

// ErrK8sUnauthorized is returned when the API server rejects the credentials. Discovery cannot
// proceed, so this is an error rather than a gap.
var ErrK8sUnauthorized = errors.New("kubernetes API rejected the credentials (401)")

// K8sDiscoveryConfig is the explicit configuration for one cluster. There are no ambient credentials.
type K8sDiscoveryConfig struct {
	ClusterName string // stable label used in canonical IDs, e.g. "kind-bas-lab"
	APIServer   string // https://host:port
	Token       string // bearer token of a read-only service account
	CAPEM       []byte // cluster CA; when empty the system roots are used
	Namespace   string // optional: restrict namespaced lists to one namespace
	PageLimit   int    // items per request (default 500)
	MaxPages    int    // hard cap on pages per list (default 200)
}

// K8sDiscoveryClient reads a Kubernetes API server. It has no write method.
type K8sDiscoveryClient struct {
	cfg  K8sDiscoveryConfig
	http *http.Client
}

// NewK8sDiscoveryClient validates the configuration. The API server must be https, and a token is required.
func NewK8sDiscoveryClient(cfg K8sDiscoveryConfig) (*K8sDiscoveryClient, error) {
	if strings.TrimSpace(cfg.ClusterName) == "" {
		return nil, errors.New("kubernetes discovery: cluster name is required")
	}
	base, err := url.Parse(cfg.APIServer)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, errors.New("kubernetes discovery: the API server must be an https URL")
	}
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, errors.New("kubernetes discovery: a read-only service account token is required")
	}
	cfg.APIServer = strings.TrimRight(cfg.APIServer, "/")
	if cfg.PageLimit <= 0 {
		cfg.PageLimit = k8sDefaultPage
	}
	if cfg.MaxPages <= 0 {
		cfg.MaxPages = k8sDefaultMaxPage
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(cfg.CAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.CAPEM) {
			return nil, errors.New("kubernetes discovery: the cluster CA PEM could not be parsed")
		}
		tlsCfg.RootCAs = pool
	}
	return &K8sDiscoveryClient{
		cfg:  cfg,
		http: &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}},
	}, nil
}

// K8sDiscoveryReport says what was read and whether the inventory is complete.
type K8sDiscoveryReport struct {
	Source      string
	ClusterName string
	ObservedAt  time.Time
	Complete    bool
	Gaps        []string
	Counts      map[string]int
}

// K8sInventory is the discovered graph fragment for one cluster.
type K8sInventory struct {
	Resources   []*CloudResource
	Identities  []*CloudIdentity
	Permissions []*CloudPermission
	// Unresolved lists bindings whose role was not listed. The access their subjects get through them is
	// unknown, not absent, so the analysis must not treat those subjects as denied.
	Unresolved []K8sUnresolvedBinding
	// Roles holds the rules of each listed Role and ClusterRole, keyed by canonical ID.
	Roles map[string][]RBACRule
}

// K8sUnresolvedBinding is a binding whose role was not in the inventory.
type K8sUnresolvedBinding struct {
	Binding     string
	BindingKind string
	Namespace   string
	RoleKind    string
	RoleName    string
	SubjectIDs  []string
}

// get performs one GET. It is the only request method the client has.
func (c *K8sDiscoveryClient) get(ctx context.Context, path string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.APIServer+path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, k8sMaxBody+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(body) > k8sMaxBody {
		return nil, resp.StatusCode, errors.New("response exceeds the size limit")
	}
	return body, resp.StatusCode, nil
}

// list reads every page of one list. It returns the items read so far and a gap description when the
// list is not complete. Only an unauthorized response or a cancelled context is returned as an error.
func (c *K8sDiscoveryClient) list(ctx context.Context, path string) ([]json.RawMessage, string, error) {
	var items []json.RawMessage
	token := ""
	for page := 0; page < c.cfg.MaxPages; page++ {
		q := url.Values{}
		q.Set("limit", strconv.Itoa(c.cfg.PageLimit))
		if token != "" {
			q.Set("continue", token)
		}
		body, status, err := c.get(ctx, path+"?"+q.Encode())
		if ctxErr := ctx.Err(); ctxErr != nil {
			return items, "", ctxErr
		}
		if err != nil {
			return items, fmt.Sprintf("%s: request failed (%v)", path, err), nil
		}
		switch {
		case status == http.StatusUnauthorized:
			return nil, "", ErrK8sUnauthorized
		case status == http.StatusForbidden:
			return items, fmt.Sprintf("forbidden: %s", path), nil
		case status != http.StatusOK:
			return items, fmt.Sprintf("%s: HTTP %d", path, status), nil
		}
		var pageBody struct {
			Items    []json.RawMessage `json:"items"`
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(body, &pageBody); err != nil {
			return items, fmt.Sprintf("%s: unreadable response", path), nil
		}
		items = append(items, pageBody.Items...)
		token = pageBody.Metadata.Continue
		if token == "" {
			return items, "", nil
		}
	}
	return items, fmt.Sprintf("%s: stopped after %d pages; inventory is partial", path, c.cfg.MaxPages), nil
}

// scopedPath returns the list path for a resource, restricted to the configured namespace when the
// resource is namespaced.
func (c *K8sDiscoveryClient) scopedPath(group, version, resource string, namespaced bool) string {
	base := "/api/v1"
	if group != "" {
		base = "/apis/" + group + "/" + version
	}
	if namespaced && c.cfg.Namespace != "" {
		return base + "/namespaces/" + url.PathEscape(c.cfg.Namespace) + "/" + resource
	}
	return base + "/" + resource
}

// k8sOwnerRef is one owner reference on a workload object.
type k8sOwnerRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// k8sPolicyRule is one RBAC rule. The JSON tags match the API, so the stored attribute keeps its shape.
type k8sPolicyRule struct {
	APIGroups       []string `json:"apiGroups"`
	Resources       []string `json:"resources"`
	ResourceNames   []string `json:"resourceNames"`
	Verbs           []string `json:"verbs"`
	NonResourceURLs []string `json:"nonResourceURLs"`
}

// toRBACRules converts API rules into evaluator rules.
func toRBACRules(in []k8sPolicyRule) []RBACRule {
	out := make([]RBACRule, 0, len(in))
	for _, r := range in {
		out = append(out, RBACRule{APIGroups: r.APIGroups, Resources: r.Resources, ResourceNames: r.ResourceNames, Verbs: r.Verbs, NonResourceURLs: r.NonResourceURLs})
	}
	return out
}

// k8sObject is the subset of Kubernetes objects discovery reads.
type k8sObject struct {
	Metadata struct {
		Name            string        `json:"name"`
		Namespace       string        `json:"namespace"`
		OwnerReferences []k8sOwnerRef `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		ServiceAccountName string `json:"serviceAccountName"`
	} `json:"spec"`
	Rules    []k8sPolicyRule `json:"rules"`
	Subjects []struct {
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"subjects"`
	RoleRef struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"roleRef"`
}

// k8sSubjectID returns the canonical identity of a binding subject, or false for a kind discovery does not model.
func k8sSubjectID(cluster, kind, name, namespace, bindingNS string) (string, bool) {
	switch kind {
	case "ServiceAccount":
		if namespace == "" {
			namespace = bindingNS
		}
		return k8sCanonicalID(cluster, namespace, "serviceaccount", name), true
	case "User":
		return k8sCanonicalID(cluster, "", "user", name), true
	case "Group":
		return k8sCanonicalID(cluster, "", "group", name), true
	}
	return "", false
}

// k8sCanonicalID builds a stable identifier. Cluster-scoped objects use the _cluster namespace segment.
func k8sCanonicalID(cluster, namespace, kind, name string) string {
	if namespace == "" {
		namespace = k8sClusterNS
	}
	return "k8s://" + cluster + "/" + namespace + "/" + kind + "/" + name
}

func k8sProvenance(list string, now time.Time) *Provenance {
	return &Provenance{Source: k8sSource + ":" + list, ObservedAt: now, Confidence: "observed"}
}

// Discover reads the cluster and returns the inventory and a report. Gaps are recorded in the report.
// An error is returned only when no inventory can be trusted at all.
func (c *K8sDiscoveryClient) Discover(ctx context.Context) (*K8sInventory, *K8sDiscoveryReport, error) {
	now := time.Now().UTC()
	cluster := c.cfg.ClusterName
	rep := &K8sDiscoveryReport{Source: k8sSource, ClusterName: cluster, ObservedAt: now, Counts: map[string]int{}}
	rbac := "rbac.authorization.k8s.io"

	type listSpec struct {
		key  string
		path string
	}
	specs := []listSpec{
		{"namespaces", "/api/v1/namespaces"},
		{"pods", c.scopedPath("", "v1", "pods", true)},
		{"serviceaccounts", c.scopedPath("", "v1", "serviceaccounts", true)},
		{"roles", c.scopedPath(rbac, "v1", "roles", true)},
		{"clusterroles", c.scopedPath(rbac, "v1", "clusterroles", false)},
		{"rolebindings", c.scopedPath(rbac, "v1", "rolebindings", true)},
		{"clusterrolebindings", c.scopedPath(rbac, "v1", "clusterrolebindings", false)},
		{"replicasets", c.scopedPath("apps", "v1", "replicasets", true)},
		{"deployments", c.scopedPath("apps", "v1", "deployments", true)},
		{"statefulsets", c.scopedPath("apps", "v1", "statefulsets", true)},
		{"daemonsets", c.scopedPath("apps", "v1", "daemonsets", true)},
		{"jobs", c.scopedPath("batch", "v1", "jobs", true)},
		{"cronjobs", c.scopedPath("batch", "v1", "cronjobs", true)},
		{"helmcharts", c.scopedPath("helm.cattle.io", "v1", "helmcharts", true)},
	}
	raw := map[string][]json.RawMessage{}
	optionalLists := map[string]bool{"helmcharts": true}
	for _, s := range specs {
		items, gap, err := c.list(ctx, s.path)
		if err != nil {
			return nil, nil, err
		}
		// An optional list is a CRD that may not be installed. Its absence (404) means there are no such
		// objects, not that they are unknown. Any other failure is still a gap.
		if optionalLists[s.key] && strings.HasSuffix(gap, ": HTTP 404") {
			gap = ""
		}
		raw[s.key] = items
		rep.Counts[s.key] = len(items)
		if gap != "" {
			rep.Gaps = append(rep.Gaps, gap)
		}
	}

	inv := &K8sInventory{Roles: map[string][]RBACRule{}}
	resources := map[string]*CloudResource{}
	identities := map[string]*CloudIdentity{}
	addResource := func(id, kind, namespace, name string, attrs map[string]string, list string) *CloudResource {
		if r, ok := resources[id]; ok {
			return r
		}
		r := &CloudResource{
			CanonicalID:  id,
			Kind:         kind,
			AccountScope: &AccountScope{Provider: "kubernetes", AccountID: cluster},
			DisplayName:  name,
			Attributes:   attrs,
			Provenance:   k8sProvenance(list, now),
		}
		if namespace != "" {
			r.Attributes["namespace"] = namespace
		}
		resources[id] = r
		inv.Resources = append(inv.Resources, r)
		return r
	}
	addIdentity := func(id, kind, namespace, name string, list string) *CloudIdentity {
		if i, ok := identities[id]; ok {
			return i
		}
		attrs := map[string]string{"name": name}
		if namespace != "" {
			attrs["namespace"] = namespace
		}
		i := &CloudIdentity{
			CanonicalID:  id,
			Kind:         kind,
			AccountScope: &AccountScope{Provider: "kubernetes", AccountID: cluster},
			Attributes:   attrs,
			Provenance:   k8sProvenance(list, now),
		}
		identities[id] = i
		inv.Identities = append(inv.Identities, i)
		return i
	}
	parse := func(key string) []k8sObject {
		var out []k8sObject
		for _, item := range raw[key] {
			var o k8sObject
			if err := json.Unmarshal(item, &o); err != nil {
				rep.Gaps = append(rep.Gaps, fmt.Sprintf("%s: an item could not be read", key))
				continue
			}
			out = append(out, o)
		}
		return out
	}

	// Workloads: index every listed workload and its owner, so each pod resolves to its top-level workload.
	workloadLists := []struct{ list, kind string }{
		{"replicasets", "ReplicaSet"}, {"deployments", "Deployment"}, {"statefulsets", "StatefulSet"},
		{"daemonsets", "DaemonSet"}, {"jobs", "Job"}, {"cronjobs", "CronJob"}, {"helmcharts", "HelmChart"},
	}
	listedWorkloads := map[string]bool{}
	ownerIndex := map[string]k8sOwnerRef{}
	for _, w := range workloadLists {
		for _, o := range parse(w.list) {
			ns, name := o.Metadata.Namespace, o.Metadata.Name
			listedWorkloads[ns+"/"+w.kind+"/"+name] = true
			if len(o.Metadata.OwnerReferences) > 0 {
				ownerIndex[ns+"/"+w.kind+"/"+name] = o.Metadata.OwnerReferences[0]
			}
			kl := strings.ToLower(w.kind)
			addResource(k8sCanonicalID(cluster, ns, kl, name), "k8s:"+kl, ns, name, map[string]string{}, w.list)
		}
	}
	gapSeen := map[string]bool{}
	// resolveWorkload follows owner references to the top of the chain. It returns "" when an owner was not
	// listed; that is recorded as a gap, so an unknown owner is never shown as a workload.
	resolveWorkload := func(pod k8sObject) (string, string) {
		ns := pod.Metadata.Namespace
		if len(pod.Metadata.OwnerReferences) == 0 {
			return k8sCanonicalID(cluster, ns, "pod", pod.Metadata.Name), "k8s:pod"
		}
		cur := pod.Metadata.OwnerReferences[0]
		// A Node owns static pods. A Node is not a workload, so the pod stands alone.
		if cur.Kind == "Node" {
			return k8sCanonicalID(cluster, ns, "pod", pod.Metadata.Name), "k8s:pod"
		}
		for hop := 0; hop < 4; hop++ {
			key := ns + "/" + cur.Kind + "/" + cur.Name
			if !listedWorkloads[key] {
				gap := fmt.Sprintf("pod %s: owner %s %s was not listed", pod.Metadata.Name, cur.Kind, cur.Name)
				if !gapSeen[gap] {
					gapSeen[gap] = true
					rep.Gaps = append(rep.Gaps, gap)
				}
				return "", ""
			}
			up, ok := ownerIndex[key]
			if !ok {
				kl := strings.ToLower(cur.Kind)
				return k8sCanonicalID(cluster, ns, kl, cur.Name), "k8s:" + kl
			}
			cur = up
		}
		gap := fmt.Sprintf("pod %s: owner chain deeper than 4 levels", pod.Metadata.Name)
		if !gapSeen[gap] {
			gapSeen[gap] = true
			rep.Gaps = append(rep.Gaps, gap)
		}
		return "", ""
	}
	for _, n := range parse("namespaces") {
		addResource(k8sCanonicalID(cluster, "", "namespace", n.Metadata.Name), "k8s:namespace", "", n.Metadata.Name, map[string]string{}, "namespaces")
	}
	for _, sa := range parse("serviceaccounts") {
		addIdentity(k8sCanonicalID(cluster, sa.Metadata.Namespace, "serviceaccount", sa.Metadata.Name), "k8s:serviceaccount", sa.Metadata.Namespace, sa.Metadata.Name, "serviceaccounts")
	}
	for _, p := range parse("pods") {
		sa := p.Spec.ServiceAccountName
		if sa == "" {
			sa = "default"
		}
		attrs := map[string]string{"serviceAccount": sa}
		if len(p.Metadata.OwnerReferences) > 0 {
			attrs["ownerKind"] = p.Metadata.OwnerReferences[0].Kind
			attrs["ownerName"] = p.Metadata.OwnerReferences[0].Name
		}
		if id, kind := resolveWorkload(p); id != "" {
			attrs["workload"] = id
			attrs["workloadKind"] = kind
		}
		addResource(k8sCanonicalID(cluster, p.Metadata.Namespace, "pod", p.Metadata.Name), "k8s:pod", p.Metadata.Namespace, p.Metadata.Name, attrs, "pods")
		addIdentity(k8sCanonicalID(cluster, p.Metadata.Namespace, "serviceaccount", sa), "k8s:serviceaccount", p.Metadata.Namespace, sa, "pods")
	}
	rulesAttr := func(o k8sObject) map[string]string {
		b, err := json.Marshal(o.Rules)
		if err != nil {
			return map[string]string{}
		}
		return map[string]string{"rules": string(b)}
	}
	for _, r := range parse("roles") {
		roleID := k8sCanonicalID(cluster, r.Metadata.Namespace, "role", r.Metadata.Name)
		addResource(roleID, "k8s:role", r.Metadata.Namespace, r.Metadata.Name, rulesAttr(r), "roles")
		inv.Roles[roleID] = toRBACRules(r.Rules)
	}
	for _, r := range parse("clusterroles") {
		roleID := k8sCanonicalID(cluster, "", "clusterrole", r.Metadata.Name)
		addResource(roleID, "k8s:clusterrole", "", r.Metadata.Name, rulesAttr(r), "clusterroles")
		inv.Roles[roleID] = toRBACRules(r.Rules)
	}

	// unlisted tracks role references whose target was not in any list, so each is reported once.
	unlisted := map[string]bool{}
	bindPermissions := func(bindings []k8sObject, bindingKind string) {
		for _, b := range bindings {
			roleID := ""
			switch b.RoleRef.Kind {
			case "ClusterRole":
				roleID = k8sCanonicalID(cluster, "", "clusterrole", b.RoleRef.Name)
			default:
				roleID = k8sCanonicalID(cluster, b.Metadata.Namespace, "role", b.RoleRef.Name)
			}
			role, ok := resources[roleID]
			if !ok {
				if !unlisted[roleID] {
					unlisted[roleID] = true
					rep.Gaps = append(rep.Gaps, fmt.Sprintf("%s %s references %s %q, which was not listed", bindingKind, b.Metadata.Name, b.RoleRef.Kind, b.RoleRef.Name))
				}
				u := K8sUnresolvedBinding{Binding: b.Metadata.Name, BindingKind: bindingKind, Namespace: b.Metadata.Namespace, RoleKind: b.RoleRef.Kind, RoleName: b.RoleRef.Name}
				for _, s := range b.Subjects {
					if sid, ok := k8sSubjectID(cluster, s.Kind, s.Name, s.Namespace, b.Metadata.Namespace); ok {
						u.SubjectIDs = append(u.SubjectIDs, sid)
					}
				}
				inv.Unresolved = append(inv.Unresolved, u)
				continue
			}
			for _, s := range b.Subjects {
				var ident *CloudIdentity
				switch s.Kind {
				case "ServiceAccount":
					ns := s.Namespace
					if ns == "" {
						ns = b.Metadata.Namespace
					}
					ident = addIdentity(k8sCanonicalID(cluster, ns, "serviceaccount", s.Name), "k8s:serviceaccount", ns, s.Name, "rolebindings")
				case "User":
					ident = addIdentity(k8sCanonicalID(cluster, "", "user", s.Name), "k8s:user", "", s.Name, "clusterrolebindings")
				case "Group":
					ident = addIdentity(k8sCanonicalID(cluster, "", "group", s.Name), "k8s:group", "", s.Name, "clusterrolebindings")
				default:
					rep.Gaps = append(rep.Gaps, fmt.Sprintf("%s %s has an unknown subject kind %q", bindingKind, b.Metadata.Name, s.Kind))
					continue
				}
				inv.Permissions = append(inv.Permissions, &CloudPermission{
					Source:     ident,
					Target:     role,
					Action:     "k8s:bind",
					SourceType: "k8s-rbac",
					Attributes: map[string]string{
						"binding":     b.Metadata.Name,
						"bindingKind": bindingKind,
						"namespace":   b.Metadata.Namespace,
						"roleKind":    b.RoleRef.Kind,
					},
					Provenance: k8sProvenance(strings.ToLower(bindingKind)+"s", now),
				})
			}
		}
	}
	bindPermissions(parse("rolebindings"), "RoleBinding")
	bindPermissions(parse("clusterrolebindings"), "ClusterRoleBinding")

	rep.Counts["resources"] = len(inv.Resources)
	rep.Counts["identities"] = len(inv.Identities)
	rep.Counts["permissions"] = len(inv.Permissions)
	rep.Complete = len(rep.Gaps) == 0
	return inv, rep, nil
}
