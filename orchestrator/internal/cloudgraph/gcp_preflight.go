package cloudgraph

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	crm "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/googleapi"
)

// Preflight probes each Google read that discovery depends on, one call per
// check, and names the one that fails. It reads only and never writes to the
// project. A later check still runs when an earlier one fails.
//
// Ancestor checks come from the same ancestry read discovery uses, so a folder
// or organization the project sits under is checked for IAM access too. When
// the ancestry read fails, the ancestor checks are SKIPPED.
func (c *GCPDiscoveryClient) Preflight(ctx context.Context) []PreflightCheck {
	var checks []PreflightCheck
	projectCanonical := "projects/" + c.projectID

	ancestors, ancErr := c.projectAncestors(ctx)
	checks = append(checks, gcpPreflight("project-ancestry-readable",
		"project ancestry is readable",
		"project ancestry not readable (needs resourcemanager.projects.get)",
		ancErr))

	checks = append(checks, gcpPreflight("project-iam-readable",
		"project IAM policy is readable",
		"project IAM policy not readable (needs resourcemanager.projects.getIamPolicy)",
		func() error {
			_, err := c.crm.Projects.GetIamPolicy(projectCanonical, &crm.GetIamPolicyRequest{}).Context(ctx).Do()
			return err
		}()))

	if ancErr != nil {
		checks = append(checks, PreflightCheck{Name: "ancestor-iam-readable", Status: "SKIPPED", Detail: "ancestry not readable, so ancestors are unknown"})
	}
	for _, anc := range ancestors {
		checks = append(checks, gcpPreflight("ancestor-iam-readable:"+anc.canonical,
			"ancestor IAM policy is readable",
			fmt.Sprintf("ancestor IAM policy not readable for %s (needs getIamPolicy on it)", anc.canonical),
			c.preflightAncestorIAM(ctx, anc)))
	}

	checks = append(checks, gcpPreflight("deny-policies-readable",
		"deny policies on the project are readable",
		"deny policies not readable (needs iam.denypolicies.list on the project)",
		func() error {
			attachment := "policies/cloudresourcemanager.googleapis.com%2Fprojects%2F" + c.projectID + "/denypolicies"
			_, err := c.iamDeny.Policies.ListPolicies(attachment).Context(ctx).Do()
			return err
		}()))

	checks = append(checks, gcpPreflight("buckets-readable",
		"buckets are listable",
		"buckets not listable (needs storage.buckets.list)",
		func() error {
			_, err := c.storage.Buckets.List(c.projectID).MaxResults(1).Context(ctx).Do()
			return err
		}()))

	checks = append(checks, gcpPreflight("service-accounts-readable",
		"service accounts are listable",
		"service accounts not listable (needs iam.serviceAccounts.list)",
		func() error {
			_, err := c.iam.Projects.ServiceAccounts.List("projects/" + c.projectID).PageSize(1).Context(ctx).Do()
			return err
		}()))
	return checks
}

// preflightAncestorIAM reads one ancestor's IAM policy through the same client
// discovery uses for it.
func (c *GCPDiscoveryClient) preflightAncestorIAM(ctx context.Context, anc gcpAncestor) error {
	_, err := c.ancestorBindings(ctx, anc)
	return err
}

// gcpPreflight maps one read's outcome to a check. A 401, 403 or 404 is a
// permission gap and gets the supplied explanation. Other errors are reported
// with their code, not guessed at.
func gcpPreflight(name, passDetail, gapDetail string, err error) PreflightCheck {
	if err == nil {
		return PreflightCheck{Name: name, Status: "PASS", Detail: passDetail}
	}
	var gerr *googleapi.Error
	if errors.As(err, &gerr) {
		switch gerr.Code {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return PreflightCheck{Name: name, Status: "FAIL", Detail: fmt.Sprintf("%s (HTTP %d)", gapDetail, gerr.Code)}
		default:
			return PreflightCheck{Name: name, Status: "FAIL", Detail: fmt.Sprintf("unexpected HTTP %d: %s", gerr.Code, gerr.Message)}
		}
	}
	return PreflightCheck{Name: name, Status: "FAIL", Detail: fmt.Sprintf("%s: %v", gapDetail, err)}
}
