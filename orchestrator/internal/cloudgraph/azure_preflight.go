package cloudgraph

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// PreflightCheck is one prerequisite of Azure discovery, reported on its own so
// the blocking gap is named exactly. Status is PASS, FAIL or SKIPPED.
type PreflightCheck struct {
	Name   string
	Status string
	Detail string
}

// Preflight verifies, one at a time, every tenant condition the Azure
// discovery pass depends on. Each failure names its own cause: a token that
// will not issue, a subscription the principal cannot see, or a Graph
// permission that has no admin consent. It reads only; it never writes to
// the tenant. A later check still runs when an earlier one fails, so one run
// shows every gap at once.
func (c *AzureDiscoveryClient) Preflight(ctx context.Context) []PreflightCheck {
	var checks []PreflightCheck

	graphTokenOK := c.preflightToken(ctx, c.graphTokens, "token-graph", &checks)
	armTokenOK := c.preflightToken(ctx, c.armTokens, "token-arm", &checks)

	subURL := fmt.Sprintf("%s/subscriptions/%s?api-version=2020-01-01", c.ARMBaseURL, c.subscriptionID)
	if armTokenOK {
		checks = append(checks, c.preflightGET(ctx, "subscription-visible", subURL, c.armTokens,
			"subscription is visible to this principal",
			"subscription not visible: no Azure subscription exists for this id, or the principal has no role on it"))
	} else {
		checks = append(checks, PreflightCheck{Name: "subscription-visible", Status: "SKIPPED", Detail: "ARM token did not issue"})
	}

	if armTokenOK {
		rbacURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$top=1", c.ARMBaseURL, c.subscriptionID)
		checks = append(checks, c.preflightGET(ctx, "rbac-readable", rbacURL, c.armTokens,
			"role assignments are readable",
			"role assignments not readable: the principal needs Reader (or Microsoft.Authorization/roleAssignments/read) on the subscription"))
		denyURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Authorization/denyAssignments?api-version=2022-04-01&$top=1", c.ARMBaseURL, c.subscriptionID)
		checks = append(checks, c.preflightGET(ctx, "deny-assignments-readable", denyURL, c.armTokens,
			"deny assignments are readable",
			"deny assignments not readable: without them a blocked grant would be reported as usable"))
	} else {
		checks = append(checks, PreflightCheck{Name: "rbac-readable", Status: "SKIPPED", Detail: "ARM token did not issue"})
		checks = append(checks, PreflightCheck{Name: "deny-assignments-readable", Status: "SKIPPED", Detail: "ARM token did not issue"})
	}

	if graphTokenOK {
		checks = append(checks, c.preflightGET(ctx, "graph-users-readable", c.GraphBaseURL+"/users?$top=1", c.graphTokens,
			"Graph users are readable (User.Read.All consented)",
			"Graph users not readable: User.Read.All has no admin consent in this tenant"))
		checks = append(checks, c.preflightGET(ctx, "graph-service-principals-readable", c.GraphBaseURL+"/servicePrincipals?$top=1", c.graphTokens,
			"Graph service principals are readable (Application.Read.All consented)",
			"Graph service principals not readable: Application.Read.All has no admin consent in this tenant"))
	} else {
		checks = append(checks, PreflightCheck{Name: "graph-users-readable", Status: "SKIPPED", Detail: "Graph token did not issue"})
		checks = append(checks, PreflightCheck{Name: "graph-service-principals-readable", Status: "SKIPPED", Detail: "Graph token did not issue"})
	}
	return checks
}

// preflightToken records whether a token source issues a token. The error text
// is passed through Redact with the client secret, since a token failure can
// echo request details.
func (c *AzureDiscoveryClient) preflightToken(ctx context.Context, tokens interface {
	Token(context.Context) (string, error)
}, name string, checks *[]PreflightCheck) bool {
	if _, err := tokens.Token(ctx); err != nil {
		*checks = append(*checks, PreflightCheck{
			Name:   name,
			Status: "FAIL",
			Detail: "token request failed: " + Redact(err.Error(), c.secret),
		})
		return false
	}
	*checks = append(*checks, PreflightCheck{Name: name, Status: "PASS", Detail: "token issued"})
	return true
}

// preflightGET issues one authenticated read and maps the status to a check.
// A 401 or 403 is a permission gap and gets the supplied explanation; any other
// non-200 is reported with its code, not guessed at.
func (c *AzureDiscoveryClient) preflightGET(ctx context.Context, name, url string, tokens interface {
	Token(context.Context) (string, error)
}, passDetail, gapDetail string) PreflightCheck {
	resp, err := c.getWith(ctx, url, tokens)
	if err != nil {
		return PreflightCheck{Name: name, Status: "FAIL", Detail: Redact(err.Error(), c.secret)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	switch {
	case resp.StatusCode == http.StatusOK:
		return PreflightCheck{Name: name, Status: "PASS", Detail: passDetail}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound:
		return PreflightCheck{Name: name, Status: "FAIL", Detail: fmt.Sprintf("%s (HTTP %d)", gapDetail, resp.StatusCode)}
	default:
		return PreflightCheck{Name: name, Status: "FAIL", Detail: fmt.Sprintf("unexpected HTTP %d: %s", resp.StatusCode, Redact(strings.TrimSpace(string(body)), c.secret))}
	}
}

// getWith is get() with an explicit token source, used by the preflight so it
// can probe Graph and ARM with the same retry and throttling the passes use.
func (c *AzureDiscoveryClient) getWith(ctx context.Context, url string, tokens interface {
	Token(context.Context) (string, error)
}) (*http.Response, error) {
	return doWithRetry(ctx, c.httpClient, c.limiter, c.retry, func(ctx context.Context) (*http.Request, error) {
		token, err := tokens.Token(ctx)
		if err != nil {
			return nil, fmt.Errorf("azure preflight: acquiring token: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("azure preflight: building request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		return req, nil
	})
}
