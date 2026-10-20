package cloudgraph

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
	crm "google.golang.org/api/cloudresourcemanager/v1"
	crmv2 "google.golang.org/api/cloudresourcemanager/v2"
	iamv1 "google.golang.org/api/iam/v1"
	iamv2 "google.golang.org/api/iam/v2"
	"google.golang.org/api/option"
	storage "google.golang.org/api/storage/v1"
	htransport "google.golang.org/api/transport/http"
)

// GCPDiscoveryStats records what a GCP pass could not model. Nothing here is
// silently dropped: each counter is a case the GCPEvaluator cannot decide.
type GCPDiscoveryStats struct {
	DiscoveryStats
	ConditionalBindings    int // IAM Conditions; emitted as conditional edges, the condition is not evaluated
	UnmappedMembers        int // allUsers, allAuthenticatedUsers, domain:, deleted principals; no single identity
	UnmappedDenyPrincipals int // deny principals whose form is not recognised
	ConditionalDenyRules   int // deny rules with a condition; emitted as conditional, the condition is not evaluated
	DenyRules              int // deny rules read from project-level deny policies
}

// retryTransport wraps the authenticated HTTP transport so every Google API
// call -- from any service client -- gets the same throttling and transient
// retry as the Azure path, without each caller re-implementing it.
type retryTransport struct {
	next    http.RoundTripper
	limiter *rate.Limiter
	policy  RetryPolicy
}

// RoundTrip retries throttled and 5xx responses. The request body is buffered
// once so it can be replayed; the original request is never mutated.
func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("gcp discovery: buffering request body: %w", err)
		}
		body = b
	}
	attempts := max(t.policy.MaxAttempts, 1)
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if t.limiter != nil {
			if err := t.limiter.Wait(req.Context()); err != nil {
				return nil, err
			}
		}
		r := req.Clone(req.Context())
		if body != nil {
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}
		resp, err := t.next.RoundTrip(r)
		var retryAfter time.Duration
		if err == nil {
			if !retryableStatus(resp.StatusCode) || attempt == attempts {
				return resp, nil
			}
			retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			resp.Body.Close()
		} else {
			if req.Context().Err() != nil {
				return nil, err
			}
			lastErr = err
		}
		if attempt == attempts {
			break
		}
		if err := sleepCtx(req.Context(), t.policy.backoff(attempt, retryAfter)); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("gave up after %d attempts: %w", attempts, lastErr)
}

// GCPDiscoveryClient discovers one GCP project's IAM identities, project and
// bucket bindings, role permissions, and project-level deny rules, and
// normalizes them for GCPEvaluator. Scope IDs follow the evaluator's prefix
// convention: projects/<id> and projects/<id>/buckets/<name>.
type GCPDiscoveryClient struct {
	projectID string
	crm       *crm.Service
	crm2      *crmv2.Service // folders are read through v2
	iam       *iamv1.Service
	iamDeny   *iamv2.Service
	storage   *storage.Service
	maxPages  int
}

// NewGCPDiscoveryClient builds the Google API clients for projectID. Auth
// comes from Application Default Credentials unless opts overrides it (tests
// pass option.WithoutAuthentication and an endpoint).
func NewGCPDiscoveryClient(ctx context.Context, projectID string, opts ...option.ClientOption) (*GCPDiscoveryClient, error) {
	if projectID == "" {
		return nil, fmt.Errorf("gcp discovery: project ID is required")
	}
	base, _, err := htransport.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcp discovery: building authenticated transport: %w", err)
	}
	base.Transport = &retryTransport{
		next:    base.Transport,
		limiter: DefaultRateLimiter(),
		policy:  DefaultRetryPolicy,
	}
	clientOpts := append([]option.ClientOption{option.WithHTTPClient(base)}, opts...)

	crm, err := crm.NewService(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("gcp discovery: cloud resource manager client: %w", err)
	}
	crm2, err := crmv2.NewService(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("gcp discovery: cloud resource manager v2 client: %w", err)
	}
	iamSvc, err := iamv1.NewService(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("gcp discovery: iam client: %w", err)
	}
	denySvc, err := iamv2.NewService(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("gcp discovery: iam v2 client: %w", err)
	}
	st, err := storage.NewService(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("gcp discovery: storage client: %w", err)
	}
	return &GCPDiscoveryClient{
		projectID: projectID,
		crm:       crm,
		crm2:      crm2,
		iam:       iamSvc,
		iamDeny:   denySvc,
		storage:   st,
		maxPages:  maxDiscoveryPages,
	}, nil
}

// gcpMemberCanonical returns the CanonicalID for an IAM member string
// ("user:x", "serviceAccount:x", "group:x"), or "" when the member cannot be
// attributed to a single identity.
func gcpMemberCanonical(member string) string {
	for _, prefix := range []string{"user:", "serviceAccount:", "group:"} {
		if strings.HasPrefix(member, prefix) {
			return "gcp:" + member
		}
	}
	return ""
}

func gcpIdentityKind(member string) string {
	switch {
	case strings.HasPrefix(member, "serviceAccount:"):
		return "gcp-service-account"
	case strings.HasPrefix(member, "group:"):
		return "gcp-group"
	default:
		return "gcp-user"
	}
}

// gcpDenyPrincipal maps a deny-rule principal URI to an IAM member string.
// Only the direct user, service account and group forms are mapped; principal
// sets and federated principals are reported as unmapped.
func gcpDenyPrincipal(p string) (string, bool) {
	switch {
	case strings.HasPrefix(p, "principal://iam.googleapis.com/projects/-/serviceAccounts/"):
		return "serviceAccount:" + strings.TrimPrefix(p, "principal://iam.googleapis.com/projects/-/serviceAccounts/"), true
	case strings.HasPrefix(p, "principal://goog/subject/"):
		return "user:" + strings.TrimPrefix(p, "principal://goog/subject/"), true
	case strings.HasPrefix(p, "principalSet://goog/group/"):
		return "group:" + strings.TrimPrefix(p, "principalSet://goog/group/"), true
	}
	return "", false
}

// gcpDenyPermission normalises a deny-rule permission such as
// "storage.googleapis.com/objects.delete" to IAM form "storage.objects.delete".
func gcpDenyPermission(p string) string {
	const sep = ".googleapis.com/"
	idx := strings.Index(p, sep)
	if idx <= 0 {
		return p
	}
	return p[:idx] + "." + p[idx+len(sep):]
}

// Discover performs one full GCP pass for the configured project. Any API
// failure aborts the pass: a partial binding set would make a missing edge
// look like a denied permission.
func (c *GCPDiscoveryClient) Discover(ctx context.Context) (*DiscoveredGraph, *GCPDiscoveryStats, error) {
	stats := &GCPDiscoveryStats{}
	graph := &DiscoveredGraph{Evaluations: map[string]PathState{}, AuditAvailability: map[string]string{}}
	acct := &AccountScope{Provider: "gcp", AccountID: c.projectID}
	provenance := func() *Provenance {
		return &Provenance{Source: "gcp:iam-bindings", Confidence: "observed"}
	}

	identities := map[string]*CloudIdentity{}
	addIdentity := func(canonical, kind string) *CloudIdentity {
		if id, ok := identities[canonical]; ok {
			return id
		}
		id := &CloudIdentity{CanonicalID: canonical, Kind: kind, AccountScope: acct, Provenance: provenance()}
		identities[canonical] = id
		graph.Identities = append(graph.Identities, id)
		stats.ItemsFound++
		return id
	}

	resources := map[string]*CloudResource{}
	addResource := func(canonical, kind string) *CloudResource {
		if r, ok := resources[canonical]; ok {
			return r
		}
		r := &CloudResource{CanonicalID: canonical, Kind: kind, AccountScope: acct, Provenance: provenance()}
		resources[canonical] = r
		graph.Resources = append(graph.Resources, r)
		stats.ItemsFound++
		return r
	}

	projectCanonical := "projects/" + c.projectID
	project := addResource(projectCanonical, "gcp-project")

	// Scopes are every place a binding can attach: the project, then each
	// bucket. Bindings at folder or organization level are not reachable from
	// a project-scoped pass and are not modelled; see the QA log.
	type scope struct {
		resource      *CloudResource
		bindings      []*crm.Binding
		inheritedFrom string // folder or organization the bindings were set on; empty for the project
	}
	projPolicy, err := c.crm.Projects.GetIamPolicy(projectCanonical, &crm.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return nil, nil, fmt.Errorf("gcp discovery: reading project IAM policy: %w", err)
	}
	scopes := []scope{{resource: project, bindings: projPolicy.Bindings}}

	ancestors, err := c.projectAncestors(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, anc := range ancestors {
		bindings, err := c.ancestorBindings(ctx, anc)
		if err != nil {
			return nil, nil, err
		}
		// Bindings above the project grant access to the project itself.
		scopes = append(scopes, scope{resource: project, bindings: bindings, inheritedFrom: anc.canonical})
	}

	bucketNames, err := c.listBuckets(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, name := range bucketNames {
		bucket := addResource(projectCanonical+"/buckets/"+name, "gcs-bucket")
		bp, err := c.storage.Buckets.GetIamPolicy(name).Context(ctx).Do()
		if err != nil {
			return nil, nil, fmt.Errorf("gcp discovery: reading IAM policy for bucket %s: %w", name, err)
		}
		var bindings []*crm.Binding
		for _, b := range bp.Bindings {
			// storage/v1 and CRM bindings share one shape for what we read.
			var cond *crm.Expr
			if b.Condition != nil {
				cond = &crm.Expr{Expression: b.Condition.Expression}
			}
			bindings = append(bindings, &crm.Binding{Role: b.Role, Members: b.Members, Condition: cond})
		}
		scopes = append(scopes, scope{resource: bucket, bindings: bindings})
	}

	// Identities: service accounts exist even with no binding yet; members
	// named in bindings are added on demand below.
	accounts, err := c.listServiceAccounts(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, sa := range accounts {
		addIdentity("gcp:serviceAccount:"+sa, "gcp-service-account")
	}

	attachments := []string{"cloudresourcemanager.googleapis.com%2Fprojects%2F" + c.projectID}
	for _, anc := range ancestors {
		attachments = append(attachments, anc.attachment)
	}
	denies, err := c.listDenyRules(ctx, attachments)
	if err != nil {
		return nil, nil, err
	}

	rolePerms := map[string][]string{}
	seen := map[string]bool{}
	for _, sc := range scopes {
		for _, b := range sc.bindings {
			conditional := b.Condition != nil
			if conditional {
				stats.ConditionalBindings++
			}
			perms, ok := rolePerms[b.Role]
			if !ok {
				perms, err = c.rolePermissions(ctx, b.Role)
				if err != nil {
					return nil, nil, err
				}
				rolePerms[b.Role] = perms
			}
			joined := strings.Join(perms, ",")
			for _, member := range b.Members {
				canonical := gcpMemberCanonical(member)
				if canonical == "" {
					stats.UnmappedMembers++
					continue
				}
				source := addIdentity(canonical, gcpIdentityKind(member))
				for _, action := range perms {
					key := canonical + "|" + action + "|" + sc.resource.CanonicalID + "|" + strconv.FormatBool(conditional)
					if seen[key] {
						continue
					}
					seen[key] = true
					attrs := map[string]string{
						"binding_scope":   sc.resource.CanonicalID,
						"binding_actions": joined,
					}
					if conditional {
						attrs["binding_condition"] = "true"
					}
					if sc.inheritedFrom != "" {
						attrs["inherited_from"] = sc.inheritedFrom
					}
					unconditionalDenies, conditionalDenies := denies.actionsFor(canonical)
					if len(unconditionalDenies) > 0 {
						attrs["deny_policy"] = "true"
						attrs["deny_scope"] = projectCanonical
						attrs["deny_actions"] = strings.Join(unconditionalDenies, ",")
					}
					if len(conditionalDenies) > 0 {
						attrs["deny_policy"] = "true"
						attrs["deny_scope"] = projectCanonical
						attrs["deny_conditional_actions"] = strings.Join(conditionalDenies, ",")
					}
					graph.Permissions = append(graph.Permissions, &CloudPermission{
						Source:     source,
						Target:     sc.resource,
						Action:     action,
						SourceType: "iam-binding",
						Attributes: attrs,
						Provenance: provenance(),
					})
					stats.ItemsFound++
				}
			}
		}
	}

	stats.DenyRules = denies.count
	stats.ConditionalDenyRules = denies.conditional
	stats.UnmappedDenyPrincipals = denies.unmapped
	return graph, stats, nil
}

// gcpDenyIndex maps a member's CanonicalID to the permissions denied to it.
// exceptions are members named in a rule's exception list for that permission
// and are never denied by that rule.
type gcpDenyIndex struct {
	denied      map[string][]gcpDeniedAction
	count       int
	unmapped    int
	conditional int
}

// gcpDeniedAction is one permission denied to a member, and whether the deny
// rule that denies it carries a condition.
type gcpDeniedAction struct {
	action      string
	conditional bool
}

// actionsFor returns the permissions denied to a member unconditionally, and
// those denied only when a condition holds.
func (d *gcpDenyIndex) actionsFor(canonical string) (unconditional, conditional []string) {
	if d == nil {
		return nil, nil
	}
	for _, da := range d.denied[canonical] {
		if da.conditional {
			conditional = append(conditional, da.action)
		} else {
			unconditional = append(unconditional, da.action)
		}
	}
	return unconditional, conditional
}

// listDenyRules reads project-level deny policies and indexes them by
// principal. Deny rules attached above the project are not visible to a
// project-scoped pass.
func (c *GCPDiscoveryClient) listDenyRules(ctx context.Context, attachments []string) (*gcpDenyIndex, error) {
	idx := &gcpDenyIndex{denied: map[string][]gcpDeniedAction{}}
	for _, attachment := range attachments {
		if err := c.collectDenyRules(ctx, "policies/"+attachment+"/denypolicies", idx); err != nil {
			return nil, err
		}
	}
	return idx, nil
}

// collectDenyRules reads every page of one attachment point's deny policies into idx.
func (c *GCPDiscoveryClient) collectDenyRules(ctx context.Context, parent string, idx *gcpDenyIndex) error {
	token := ""
	for pages := 0; ; pages++ {
		if pages >= c.maxPages {
			return fmt.Errorf("gcp discovery: more than %d pages of deny policies; refusing to continue", c.maxPages)
		}
		call := c.iamDeny.Policies.ListPolicies(parent).Context(ctx)
		if token != "" {
			call = call.PageToken(token)
		}
		resp, err := call.Do()
		if err != nil {
			return fmt.Errorf("gcp discovery: listing deny policies: %w", err)
		}
		for _, pol := range resp.Policies {
			for _, rule := range pol.Rules {
				if rule.DenyRule == nil {
					continue
				}
				idx.count++
				conditional := rule.DenyRule.DenialCondition != nil
				if conditional {
					idx.conditional++
				}
				exempt := map[string]bool{}
				for _, ex := range rule.DenyRule.ExceptionPrincipals {
					if m, ok := gcpDenyPrincipal(ex); ok {
						exempt[gcpMemberCanonical(m)] = true
					}
				}
				for _, p := range rule.DenyRule.DeniedPrincipals {
					member, ok := gcpDenyPrincipal(p)
					canonical := gcpMemberCanonical(member)
					if !ok || canonical == "" {
						idx.unmapped++
						continue
					}
					if exempt[canonical] {
						continue
					}
					for _, perm := range rule.DenyRule.DeniedPermissions {
						idx.denied[canonical] = append(idx.denied[canonical], gcpDeniedAction{
							action:      gcpDenyPermission(perm),
							conditional: conditional,
						})
					}
				}
			}
		}
		if resp.NextPageToken == "" {
			return nil
		}
		token = resp.NextPageToken
	}
}

// rolePermissions returns the included permissions of a role, predefined or
// custom. A role that cannot be read fails the pass: an empty permission set
// would silently erase every grant that role carries.
func (c *GCPDiscoveryClient) rolePermissions(ctx context.Context, role string) ([]string, error) {
	r, err := c.iam.Roles.Get(role).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("gcp discovery: reading role %s: %w", role, err)
	}
	return r.IncludedPermissions, nil
}

func (c *GCPDiscoveryClient) listBuckets(ctx context.Context) ([]string, error) {
	var names []string
	token := ""
	for pages := 0; ; pages++ {
		if pages >= c.maxPages {
			return nil, fmt.Errorf("gcp discovery: more than %d pages of buckets; refusing to continue", c.maxPages)
		}
		call := c.storage.Buckets.List(c.projectID).Context(ctx)
		if token != "" {
			call = call.PageToken(token)
		}
		out, err := call.Do()
		if err != nil {
			return nil, fmt.Errorf("gcp discovery: listing buckets: %w", err)
		}
		for _, b := range out.Items {
			names = append(names, b.Name)
		}
		if out.NextPageToken == "" {
			return names, nil
		}
		token = out.NextPageToken
	}
}

// listServiceAccounts returns service account emails in the project.
func (c *GCPDiscoveryClient) listServiceAccounts(ctx context.Context) ([]string, error) {
	var emails []string
	token := ""
	for pages := 0; ; pages++ {
		if pages >= c.maxPages {
			return nil, fmt.Errorf("gcp discovery: more than %d pages of service accounts; refusing to continue", c.maxPages)
		}
		call := c.iam.Projects.ServiceAccounts.List("projects/" + c.projectID).Context(ctx)
		if token != "" {
			call = call.PageToken(token)
		}
		out, err := call.Do()
		if err != nil {
			return nil, fmt.Errorf("gcp discovery: listing service accounts: %w", err)
		}
		for _, sa := range out.Accounts {
			emails = append(emails, sa.Email)
		}
		if out.NextPageToken == "" {
			return emails, nil
		}
		token = out.NextPageToken
	}
}
