package cloudgraph

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AWSIAMAPI is the IAM surface AWS discovery reads from. *iam.Client
// satisfies it; tests supply fakes.
type AWSIAMAPI interface {
	GetAccountAuthorizationDetails(ctx context.Context, params *iam.GetAccountAuthorizationDetailsInput, optFns ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error)
}

// AWSSTSAPI resolves the account the credentials belong to.
type AWSSTSAPI interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// AWSBackupAPI lists backup vaults, the targets of recovery-destruction
// scenarios. *backup.Client satisfies it.
type AWSBackupAPI interface {
	ListBackupVaults(ctx context.Context, params *backup.ListBackupVaultsInput, optFns ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error)
}

// AWSS3API lists buckets so they become resources that policies can target.
type AWSS3API interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
}

// AWSDiscoveryClient discovers a live AWS account's IAM identities, identity
// policies, role trust relationships, and S3 buckets, and normalizes them into
// cloudgraph's provider-agnostic types. The AWSEvaluator consumes the policy
// documents attached to each edge, so documents are kept verbatim (compacted
// only, never rewritten).
type AWSDiscoveryClient struct {
	iam AWSIAMAPI
	sts AWSSTSAPI
	s3  AWSS3API
	// org reads SCPs. Required: without it an organization's deny layers
	// would be invisible and grants would be over-reported.
	org AWSOrgAPI
	// backup is optional. Without it, vault inventory is reported as skipped
	// rather than guessed, and backup-assurance scenarios stay not-attempted.
	backup AWSBackupAPI

	region    string
	accountID string
	maxPages  int
}

// NewAWSDiscoveryClient builds a client from an SDK config. Credentials come
// from the SDK's default chain (environment, shared config, instance/role
// profile), never from a request body.
func NewAWSDiscoveryClient(cfg aws.Config) *AWSDiscoveryClient {
	return &AWSDiscoveryClient{
		iam:      iam.NewFromConfig(cfg),
		sts:      sts.NewFromConfig(cfg),
		s3:       s3.NewFromConfig(cfg),
		org:      organizations.NewFromConfig(cfg),
		backup:   backup.NewFromConfig(cfg),
		region:   cfg.Region,
		maxPages: maxDiscoveryPages,
	}
}

// NewAWSDiscoveryClientWith wires explicit API implementations. Used by tests
// and by any caller that needs to decorate the SDK clients.
func NewAWSDiscoveryClientWith(iamAPI AWSIAMAPI, stsAPI AWSSTSAPI, s3API AWSS3API, region string) *AWSDiscoveryClient {
	return &AWSDiscoveryClient{iam: iamAPI, sts: stsAPI, s3: s3API, region: region, maxPages: maxDiscoveryPages}
}

// WithOrganizations attaches the Organizations source used to read SCPs.
func (c *AWSDiscoveryClient) WithOrganizations(o AWSOrgAPI) *AWSDiscoveryClient {
	c.org = o
	return c
}

// WithBackup attaches a backup vault inventory source to the client.
func (c *AWSDiscoveryClient) WithBackup(b AWSBackupAPI) *AWSDiscoveryClient {
	c.backup = b
	return c
}

// DiscoverAccount resolves the account ID for the active credentials. Every
// other discovery call depends on it, so it runs first.
func (c *AWSDiscoveryClient) DiscoverAccount(ctx context.Context) (*AccountScope, error) {
	out, err := c.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("aws discovery: resolving caller identity: %w", err)
	}
	if out.Account == nil || *out.Account == "" {
		return nil, fmt.Errorf("aws discovery: caller identity returned no account")
	}
	c.accountID = *out.Account
	return &AccountScope{Provider: "aws", AccountID: c.accountID, Region: c.region}, nil
}

// awsAuthSnapshot is the merged result of every page of
// GetAccountAuthorizationDetails. The API returns users, roles, groups and
// managed policies in one listing, so one snapshot feeds identities and
// permissions alike.
type awsAuthSnapshot struct {
	users    []types.UserDetail
	roles    []types.RoleDetail
	groups   []types.GroupDetail
	policies []types.ManagedPolicyDetail
}

func (c *AWSDiscoveryClient) fetchAuthorizationDetails(ctx context.Context) (*awsAuthSnapshot, error) {
	snap := &awsAuthSnapshot{}
	var marker *string
	for pages := 0; ; pages++ {
		if pages >= c.maxPages {
			return nil, fmt.Errorf("aws discovery: more than %d pages of authorization details; refusing to continue", c.maxPages)
		}
		out, err := c.iam.GetAccountAuthorizationDetails(ctx, &iam.GetAccountAuthorizationDetailsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("aws discovery: listing authorization details: %w", err)
		}
		snap.users = append(snap.users, out.UserDetailList...)
		snap.roles = append(snap.roles, out.RoleDetailList...)
		snap.groups = append(snap.groups, out.GroupDetailList...)
		snap.policies = append(snap.policies, out.Policies...)
		if !out.IsTruncated || out.Marker == nil || *out.Marker == "" {
			return snap, nil
		}
		marker = out.Marker
	}
}

// awsDecodePolicy turns the policy text IAM returns into compact JSON.
// Documents from the Query API arrive URL-encoded; some SDK paths already
// decode them. Either form is accepted; anything that is not valid JSON
// afterwards is an error rather than an edge built on guessed content.
func awsDecodePolicy(raw string) (string, error) {
	doc := strings.TrimSpace(raw)
	if !strings.HasPrefix(doc, "{") {
		dec, err := url.QueryUnescape(doc)
		if err != nil {
			return "", fmt.Errorf("policy document is neither JSON nor URL-encoded JSON: %w", err)
		}
		doc = dec
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(doc)); err != nil {
		return "", fmt.Errorf("policy document is not valid JSON: %w", err)
	}
	return buf.String(), nil
}

// awsStatement is one IAM policy statement. Action, Resource and Principal are
// raw because each may be a string, a list, or (Principal) the bare "*".
type awsStatement struct {
	Effect      string          `json:"Effect"`
	Action      json.RawMessage `json:"Action"`
	NotAction   json.RawMessage `json:"NotAction"`
	Resource    json.RawMessage `json:"Resource"`
	NotResource json.RawMessage `json:"NotResource"`
	Principal   json.RawMessage `json:"Principal"`
	Condition   json.RawMessage `json:"Condition"`
}

type awsPolicyDocument struct {
	Statement json.RawMessage `json:"Statement"`
}

// parseStatements accepts Statement as either one object or an array, which
// IAM allows and real documents use both ways.
func parseStatements(compact string) ([]awsStatement, error) {
	var doc awsPolicyDocument
	if err := json.Unmarshal([]byte(compact), &doc); err != nil {
		return nil, err
	}
	raw := bytes.TrimSpace(doc.Statement)
	if len(raw) == 0 {
		return nil, nil
	}
	if raw[0] == '[' {
		var list []awsStatement
		err := json.Unmarshal(raw, &list)
		return list, err
	}
	var one awsStatement
	err := json.Unmarshal(raw, &one)
	return []awsStatement{one}, err
}

// stringOrList decodes an IAM field that may be a single string or a list.
func stringOrList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	return nil
}

// awsPrincipalARNs returns the AWS principals a trust statement names. A bare
// "*" principal and service principals are reported separately: the first is
// anyone (not attributable to a discovered identity), the second is not an
// IAM identity at all.
func awsPrincipalARNs(raw json.RawMessage) (arns []string, wildcard bool) {
	if len(raw) == 0 {
		return nil, false
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte(`"*"`)) {
		return nil, true
	}
	var p struct {
		AWS json.RawMessage `json:"AWS"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return nil, false
	}
	list := stringOrList(p.AWS)
	for _, a := range list {
		if a == "*" {
			return nil, true
		}
	}
	return list, false
}

// awsActionMatches reports whether a statement's Action pattern covers the
// named action, honouring IAM's wildcard forms.
func awsActionMatches(pattern, action string) bool {
	return globMatch(pattern, action)
}

// AWSDiscoveryStats extends DiscoveryStats with the AWS-specific cases that
// the evaluator cannot model, so none of them are silently dropped.
type AWSDiscoveryStats struct {
	DiscoveryStats
	NotActionStatements  int  // NotAction or NotResource statements; not expanded, so no edges emitted
	ConditionalAllows    int  // Allow statements with Condition; edges emitted, conditions unevaluated
	WildcardTrustSkipped int  // trust statements with Principal "*"; no attributable identity
	UnresolvedTrust      int  // trust principals (account roots, deleted-role IDs) not in inventory
	SkippedDocuments     int  // identity policies that failed to decode
	BackupVaults         int  // backup vaults discovered
	BackupVaultsSkipped  bool // no backup inventory source attached
	SCPLevels            int  // organization levels read (account, OUs, root)
	SCPNotInUse          bool // account is not in an organization; SCPs do not apply
	BoundaryAttached     int  // identities with a permissions boundary attached to their edges
	BoundaryUnresolved   int  // identities whose boundary policy was not in the snapshot; edges are Unknown
}

// Discover performs a full AWS discovery pass: account, identities, resources,
// and permission edges, returned as one DiscoveredGraph ready for CloudPlan.
// Any failure aborts the pass -- a partial inventory would make absence of an
// edge look like evidence of no access.
func (c *AWSDiscoveryClient) Discover(ctx context.Context) (*DiscoveredGraph, *AWSDiscoveryStats, error) {
	if c.accountID == "" {
		if _, err := c.DiscoverAccount(ctx); err != nil {
			return nil, nil, err
		}
	}
	snap, err := c.fetchAuthorizationDetails(ctx)
	if err != nil {
		return nil, nil, err
	}

	stats := &AWSDiscoveryStats{}
	graph := &DiscoveredGraph{Evaluations: map[string]PathState{}, AuditAvailability: map[string]string{}}

	identityByARN := map[string]*CloudIdentity{}
	groupByName := map[string]types.GroupDetail{}
	managedDoc := map[string]string{} // managed policy ARN -> default version document (compact)
	for _, g := range snap.groups {
		groupByName[aws.ToString(g.GroupName)] = g
	}
	for _, p := range snap.policies {
		arn := aws.ToString(p.Arn)
		for _, v := range p.PolicyVersionList {
			if !v.IsDefaultVersion {
				continue
			}
			doc, err := awsDecodePolicy(aws.ToString(v.Document))
			if err != nil {
				stats.SkippedDocuments++
				continue
			}
			managedDoc[arn] = doc
		}
	}

	addIdentity := func(arn, kind string) *CloudIdentity {
		id := &CloudIdentity{
			CanonicalID:  arn,
			Kind:         kind,
			AccountScope: &AccountScope{Provider: "aws", AccountID: c.accountID, Region: c.region},
			Attributes:   map[string]string{},
			Provenance:   &Provenance{Source: "aws:iam-authorization-details", Confidence: "observed"},
		}
		identityByARN[arn] = id
		graph.Identities = append(graph.Identities, id)
		stats.ItemsFound++
		return id
	}

	type policyHolder struct {
		identity *CloudIdentity
		docs     []string
		trust    string // role trust document, roles only
		boundary string // permissions boundary policy ARN, if any
	}
	var holders []*policyHolder

	for _, u := range snap.users {
		id := addIdentity(aws.ToString(u.Arn), "iam-user")
		h := &policyHolder{identity: id, boundary: awsBoundaryARN(u.PermissionsBoundary)}
		for _, pd := range u.UserPolicyList {
			h.docs = append(h.docs, aws.ToString(pd.PolicyDocument))
		}
		for _, ap := range u.AttachedManagedPolicies {
			if d, ok := managedDoc[aws.ToString(ap.PolicyArn)]; ok {
				h.docs = append(h.docs, d)
			}
		}
		for _, gname := range u.GroupList {
			g, ok := groupByName[gname]
			if !ok {
				continue
			}
			for _, pd := range g.GroupPolicyList {
				h.docs = append(h.docs, aws.ToString(pd.PolicyDocument))
			}
			for _, ap := range g.AttachedManagedPolicies {
				if d, ok := managedDoc[aws.ToString(ap.PolicyArn)]; ok {
					h.docs = append(h.docs, d)
				}
			}
		}
		holders = append(holders, h)
	}

	for _, r := range snap.roles {
		id := addIdentity(aws.ToString(r.Arn), "iam-role")
		h := &policyHolder{identity: id, boundary: awsBoundaryARN(r.PermissionsBoundary)}
		for _, pd := range r.RolePolicyList {
			h.docs = append(h.docs, aws.ToString(pd.PolicyDocument))
		}
		for _, ap := range r.AttachedManagedPolicies {
			if d, ok := managedDoc[aws.ToString(ap.PolicyArn)]; ok {
				h.docs = append(h.docs, d)
			}
		}
		h.trust = aws.ToString(r.AssumeRolePolicyDocument)
		holders = append(holders, h)
	}

	// Resources: every role is also a target (it can be assumed), and every
	// S3 bucket is a target. Policy-referenced ARNs are added on demand below.
	resourceByID := map[string]*CloudResource{}
	addResource := func(canonical, kind string) *CloudResource {
		if r, ok := resourceByID[canonical]; ok {
			return r
		}
		r := &CloudResource{
			CanonicalID:  canonical,
			Kind:         kind,
			AccountScope: &AccountScope{Provider: "aws", AccountID: c.accountID, Region: c.region},
			Provenance:   &Provenance{Source: "aws:iam-authorization-details", Confidence: "observed"},
		}
		resourceByID[canonical] = r
		graph.Resources = append(graph.Resources, r)
		return r
	}
	for _, r := range snap.roles {
		addResource(aws.ToString(r.Arn), "iam-role")
	}
	buckets, err := c.listBuckets(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, name := range buckets {
		addResource("arn:aws:s3:::"+name, "s3-bucket")
	}
	if c.backup == nil {
		stats.BackupVaultsSkipped = true
	} else {
		vaults, err := c.listBackupVaults(ctx)
		if err != nil {
			return nil, nil, err
		}
		for _, arn := range vaults {
			addResource(arn, "backup-vault")
		}
		stats.BackupVaults = len(vaults)
	}

	seen := map[string]bool{}
	emit := func(p *CloudPermission, key string) {
		if seen[key] {
			return
		}
		seen[key] = true
		graph.Permissions = append(graph.Permissions, p)
		stats.ItemsFound++
	}

	for _, h := range holders {
		for _, raw := range h.docs {
			compact, err := awsDecodePolicy(raw)
			if err != nil {
				stats.SkippedDocuments++
				continue
			}
			stmts, err := parseStatements(compact)
			if err != nil {
				stats.SkippedDocuments++
				continue
			}
			for _, st := range stmts {
				if st.Effect != "Allow" {
					continue
				}
				if len(st.NotAction) > 0 || len(st.NotResource) > 0 {
					// "everything except X" cannot be expanded here. Emitting it
					// as a wildcard edge would report access that the statement
					// does not grant, so it is counted and skipped.
					stats.NotActionStatements++
					continue
				}
				if len(st.Condition) > 0 {
					stats.ConditionalAllows++
				}
				resources := stringOrList(st.Resource)
				if len(resources) == 0 {
					resources = []string{"*"}
				}
				for _, action := range stringOrList(st.Action) {
					for _, res := range resources {
						kind := "aws-resource"
						if res == "*" {
							kind = "aws-resource-wildcard"
						}
						target := addResource(res, kind)
						emit(&CloudPermission{
							Source:     h.identity,
							Target:     target,
							Action:     action,
							SourceType: "identity-policy",
							Attributes: map[string]string{"policy_document": compact},
							Provenance: &Provenance{Source: "aws:iam-authorization-details", Confidence: "observed"},
						}, h.identity.CanonicalID+"|"+action+"|"+target.CanonicalID+"|"+compact)
					}
				}
			}
		}
	}

	// Role trust: an edge from a principal to a role exists only when the
	// principal's own identity policies also allow sts:AssumeRole on that role.
	// AWS requires both sides; a trust statement alone is not an assumable path.
	for _, h := range holders {
		if h.trust == "" {
			continue
		}
		compactTrust, err := awsDecodePolicy(h.trust)
		if err != nil {
			stats.SkippedDocuments++
			continue
		}
		stmts, err := parseStatements(compactTrust)
		if err != nil {
			stats.SkippedDocuments++
			continue
		}
		role := h.identity
		for _, st := range stmts {
			if st.Effect != "Allow" {
				continue
			}
			arns, wildcard := awsPrincipalARNs(st.Principal)
			if wildcard {
				stats.WildcardTrustSkipped++
				continue
			}
			for _, arn := range arns {
				principal, ok := identityByARN[arn]
				if !ok {
					stats.UnresolvedTrust++
					continue
				}
				if !awsIdentityAllowsAssume(principal, role.CanonicalID, graph.Permissions) {
					continue
				}
				emit(&CloudPermission{
					Source:     principal,
					Target:     resourceByID[role.CanonicalID],
					Action:     "sts:AssumeRole",
					SourceType: "role-trust",
					Attributes: map[string]string{"policy_document": compactTrust},
					Provenance: &Provenance{Source: "aws:iam-authorization-details", Confidence: "observed"},
				}, principal.CanonicalID+"|sts:AssumeRole|"+role.CanonicalID+"|trust|"+compactTrust)
			}
		}
	}

	// Enforcement layers. A boundary is per identity; SCPs are per account and
	// shared by every edge. Both are attached to the edges they constrain so the
	// evaluator can apply them with the edge alone.
	boundaryByID := map[string]string{}
	unresolvedByID := map[string]bool{}
	for _, h := range holders {
		if h.boundary == "" {
			continue
		}
		doc, ok := managedDoc[h.boundary]
		if !ok {
			unresolvedByID[h.identity.CanonicalID] = true
			stats.BoundaryUnresolved++
			continue
		}
		boundaryByID[h.identity.CanonicalID] = doc
		stats.BoundaryAttached++
	}
	levels, inOrg, err := c.scpLevels(ctx)
	if err != nil {
		return nil, nil, err
	}
	levelsJSON := ""
	if inOrg {
		stats.SCPLevels = len(levels)
		if levelsJSON, err = awsLevelsJSON(levels); err != nil {
			return nil, nil, err
		}
	} else {
		stats.SCPNotInUse = true
	}
	for _, p := range graph.Permissions {
		id := p.Source.CanonicalID
		if doc, ok := boundaryByID[id]; ok {
			p.Attributes["boundary_document"] = doc
		}
		if unresolvedByID[id] {
			p.Attributes["boundary_unresolved"] = "true"
		}
		if inOrg {
			p.Attributes["scp_levels"] = levelsJSON
		}
	}

	return graph, stats, nil
}

// awsBoundaryARN returns the permissions boundary policy ARN, or "" if none.
func awsBoundaryARN(b *types.AttachedPermissionsBoundary) string {
	if b == nil {
		return ""
	}
	return aws.ToString(b.PermissionsBoundaryArn)
}

// awsIdentityAllowsAssume reports whether any already-emitted identity-policy
// edge lets principal call sts:AssumeRole on the role. Runs after identity
// policies are emitted, so the check reads the same policy evidence the
// evaluator will.
func awsIdentityAllowsAssume(principal *CloudIdentity, roleARN string, perms []*CloudPermission) bool {
	for _, p := range perms {
		if p.SourceType != "identity-policy" || p.Source.CanonicalID != principal.CanonicalID {
			continue
		}
		if !awsActionMatches(p.Action, "sts:AssumeRole") {
			continue
		}
		if p.Target.CanonicalID == roleARN || p.Target.CanonicalID == "*" {
			return true
		}
	}
	return false
}

// listBuckets returns the account's S3 bucket names. ListBuckets is not
// paginated by the SDK's default options, so the continuation token is followed
// explicitly, bounded by the same page cap.
func (c *AWSDiscoveryClient) listBuckets(ctx context.Context) ([]string, error) {
	var names []string
	var token *string
	for pages := 0; ; pages++ {
		if pages >= c.maxPages {
			return nil, fmt.Errorf("aws discovery: more than %d pages of buckets; refusing to continue", c.maxPages)
		}
		out, err := c.s3.ListBuckets(ctx, &s3.ListBucketsInput{ContinuationToken: token})
		if err != nil {
			return nil, fmt.Errorf("aws discovery: listing S3 buckets: %w", err)
		}
		for _, b := range out.Buckets {
			names = append(names, aws.ToString(b.Name))
		}
		if out.ContinuationToken == nil || *out.ContinuationToken == "" {
			return names, nil
		}
		token = out.ContinuationToken
	}
}

// listBackupVaults returns the ARNs of the account's backup vaults, following
// NextToken under the shared page cap.
func (c *AWSDiscoveryClient) listBackupVaults(ctx context.Context) ([]string, error) {
	var arns []string
	var token *string
	for pages := 0; ; pages++ {
		if pages >= c.maxPages {
			return nil, fmt.Errorf("aws discovery: more than %d pages of backup vaults; refusing to continue", c.maxPages)
		}
		out, err := c.backup.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("aws discovery: listing backup vaults: %w", err)
		}
		for _, v := range out.BackupVaultList {
			arns = append(arns, aws.ToString(v.BackupVaultArn))
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return arns, nil
		}
		token = out.NextToken
	}
}
