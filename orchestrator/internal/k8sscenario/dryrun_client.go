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

// DryRunClient implements AdmissionClient. It reads namespaces and webhook configurations, and sends pod creates with
// dryRun=All. It has no call that persists an object.
type DryRunClient struct {
	server string
	token  string
	http   *http.Client
}

// NewDryRunClient validates the configuration. The server must be https and a token is required.
func NewDryRunClient(server, token string, caPEM []byte) (*DryRunClient, error) {
	u, err := url.Parse(server)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("the API server must be an https URL")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("a token is required for admission dry-run")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("the cluster CA PEM could not be parsed")
		}
		tlsCfg.RootCAs = pool
	}
	return &DryRunClient{server: strings.TrimRight(server, "/"), token: token,
		http: &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}}, nil
}

func (c *DryRunClient) send(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.server+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s failed: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, data, nil
}

// NamespacePSALevel returns the enforced Pod Security level of a namespace, or found=false when it does not exist.
func (c *DryRunClient) NamespacePSALevel(ctx context.Context, namespace string) (string, bool, error) {
	path := "/api/v1/namespaces/" + url.PathEscape(namespace)
	status, raw, err := c.send(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", false, err
	}
	switch status {
	case http.StatusNotFound:
		return "", false, nil
	case http.StatusOK:
	default:
		return "", false, fmt.Errorf("GET namespace: HTTP %d", status)
	}
	var ns struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &ns); err != nil {
		return "", false, errors.New("namespace response is not valid JSON")
	}
	return ns.Metadata.Labels[PSAEnforceLabel], true, nil
}

// DryRunPod sends a pod create with dryRun=All. A 2xx answer is allowed. An admission refusal (400, 403, 422) is not.
func (c *DryRunClient) DryRunPod(ctx context.Context, namespace string, pod map[string]any) (DryRunResult, error) {
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods?dryRun=All"
	status, raw, err := c.send(ctx, http.MethodPost, path, pod)
	if err != nil {
		return DryRunResult{}, err
	}
	switch {
	case status == http.StatusOK || status == http.StatusCreated:
		return DryRunResult{StatusCode: status, Allowed: true}, nil
	case status == http.StatusUnauthorized:
		return DryRunResult{StatusCode: status}, errors.New("dry-run refused (HTTP 401): the credential is not valid")
	case status == http.StatusBadRequest || status == http.StatusForbidden || status == http.StatusUnprocessableEntity:
		var st struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &st)
		return DryRunResult{StatusCode: status, Allowed: false, Reason: st.Reason, Message: st.Message}, nil
	default:
		return DryRunResult{StatusCode: status}, fmt.Errorf("dry-run create: HTTP %d", status)
	}
}

// WebhookSideEffects lists the sideEffects value of every validating and mutating webhook.
func (c *DryRunClient) WebhookSideEffects(ctx context.Context) ([]string, error) {
	var out []string
	for _, path := range []string{
		"/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations",
		"/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations",
	} {
		status, raw, err := c.send(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("GET %s: HTTP %d", path, status)
		}
		var list struct {
			Items []struct {
				Webhooks []struct {
					SideEffects string `json:"sideEffects"`
				} `json:"webhooks"`
			} `json:"items"`
		}
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, errors.New("webhook configuration response is not valid JSON")
		}
		for _, item := range list.Items {
			for _, w := range item.Webhooks {
				out = append(out, w.SideEffects)
			}
		}
	}
	return out, nil
}
