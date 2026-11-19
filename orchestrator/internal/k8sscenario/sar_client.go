package k8sscenario

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const sarPath = "/apis/authorization.k8s.io/v1/subjectaccessreviews"

// SARClient sends SubjectAccessReview requests and nothing else. It is read-only: a review is evaluated and not stored.
type SARClient struct {
	server string
	token  string
	http   *http.Client
}

// NewSARClient validates the configuration. The server must be https and a token is required. The token is used
// only in the Authorization header.
func NewSARClient(server, token string, caPEM []byte) (*SARClient, error) {
	u, err := url.Parse(server)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("the API server must be an https URL")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("a token is required for SubjectAccessReview")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("the cluster CA PEM could not be parsed")
		}
		tlsCfg.RootCAs = pool
	}
	return &SARClient{server: strings.TrimRight(server, "/"), token: token,
		http: &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}}, nil
}

// Review sends one SubjectAccessReview and returns the decision.
func (c *SARClient) Review(ctx context.Context, spec SARSpec) (SARResult, error) {
	body := map[string]any{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       "SubjectAccessReview",
		"spec": map[string]any{
			"user": spec.User,
			"resourceAttributes": map[string]string{
				"verb": spec.Verb, "group": spec.Group, "resource": spec.Resource, "namespace": spec.Namespace,
			},
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return SARResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.server+sarPath, bytes.NewReader(raw))
	if err != nil {
		return SARResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return SARResult{}, fmt.Errorf("SubjectAccessReview request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return SARResult{}, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return SARResult{StatusCode: resp.StatusCode}, fmt.Errorf("SubjectAccessReview refused (HTTP %d): the credential cannot create reviews", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return SARResult{StatusCode: resp.StatusCode}, fmt.Errorf("SubjectAccessReview: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Status struct {
			Allowed bool   `json:"allowed"`
			Denied  bool   `json:"denied"`
			Reason  string `json:"reason"`
		} `json:"status"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return SARResult{StatusCode: resp.StatusCode}, errors.New("SubjectAccessReview response is not valid JSON")
	}
	return SARResult{StatusCode: resp.StatusCode, Allowed: out.Status.Allowed, Denied: out.Status.Denied, Reason: out.Status.Reason}, nil
}
