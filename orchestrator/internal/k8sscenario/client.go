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

// ErrUnauthorized means the API server rejected the scenario credential (401 or 403).
var ErrUnauthorized = errors.New("kubernetes API rejected the scenario credential")

// ClientConfig configures the write client. The token is a short-lived scenario credential. It is never logged
// and never included in an error.
type ClientConfig struct {
	APIServer  string // https://host:port
	Token      string
	CAPEM      []byte
	HTTPClient *http.Client // optional; tests may supply one
}

// APIClient implements Client over the Kubernetes REST API. It can write only the kinds in the registry,
// and every kind is checked before a request is built, so a refused operation sends nothing.
type APIClient struct {
	base  string
	token string
	http  *http.Client
}

// readableKinds maps each kind the engine may read to its REST resource.
var readableKinds = map[string]string{"Pod": "pods", "ConfigMap": "configmaps", "Namespace": "namespaces"}

// writableKinds are the only kinds the engine may create, patch or delete.
var writableKinds = map[string]string{"Pod": "pods", "ConfigMap": "configmaps"}

// NewAPIClient validates the configuration. The API server must be https and a token is required.
func NewAPIClient(cfg ClientConfig) (*APIClient, error) {
	if !strings.HasPrefix(cfg.APIServer, "https://") {
		return nil, errors.New("the API server must be an https URL")
	}
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, errors.New("a scenario token is required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if len(cfg.CAPEM) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(cfg.CAPEM) {
				return nil, errors.New("the cluster CA PEM could not be parsed")
			}
			tlsCfg.RootCAs = pool
		}
		hc = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	}
	return &APIClient{base: strings.TrimRight(cfg.APIServer, "/"), token: cfg.Token, http: hc}, nil
}

// do sends one request. The response body is limited in size, and errors carry only the status code.
func (c *APIClient) do(ctx context.Context, method, path, contentType string, body any) (int, []byte, error) {
	return c.doAs(ctx, c.token, method, path, contentType, body)
}

// doAs sends a request with the given bearer token. The token is used only in the Authorization header.
func (c *APIClient) doAs(ctx context.Context, token, method, path, contentType string, body any) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, errors.New("request failed: " + method + " " + path)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, raw, nil
}

// statusErr converts a non-success status into an error that names the request and the status only.
func statusErr(method, path string, status int) error {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return fmt.Errorf("%s %s: %w", method, path, ErrUnauthorized)
	}
	return fmt.Errorf("%s %s: HTTP %d", method, path, status)
}

func nsPath(ns string) string { return "/api/v1/namespaces/" + url.PathEscape(ns) }

func objectPath(resource string, ref ObjectRef) string {
	return nsPath(ref.Namespace) + "/" + resource + "/" + url.PathEscape(ref.Name)
}

// NamespaceLabels reads a namespace's labels. A missing namespace is reported as absent, not as an error.
func (c *APIClient) NamespaceLabels(ctx context.Context, ns string) (map[string]string, bool, error) {
	path := "/api/v1/namespaces/" + url.PathEscape(ns)
	status, raw, err := c.do(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return nil, false, err
	}
	switch {
	case status == http.StatusNotFound:
		return nil, false, nil
	case status != http.StatusOK:
		return nil, false, statusErr(http.MethodGet, path, status)
	}
	var obj struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, false, errors.New("namespace response is not valid JSON")
	}
	return obj.Metadata.Labels, true, nil
}

// CurrentIdentity asks the API server who the credential is, using a SelfSubjectReview. It has no side effects.
func (c *APIClient) CurrentIdentity(ctx context.Context) (string, error) {
	const path = "/apis/authentication.k8s.io/v1/selfsubjectreviews"
	body := map[string]string{"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"}
	status, raw, err := c.do(ctx, http.MethodPost, path, "application/json", body)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return "", statusErr(http.MethodPost, path, status)
	}
	var review struct {
		Status struct {
			UserInfo struct {
				Username string `json:"username"`
			} `json:"userInfo"`
		} `json:"status"`
	}
	if err := json.Unmarshal(raw, &review); err != nil {
		return "", errors.New("SelfSubjectReview response is not valid JSON")
	}
	return review.Status.UserInfo.Username, nil
}

// Get reads one object. A missing object is reported as absent, not as an error.
func (c *APIClient) Get(ctx context.Context, ref ObjectRef) (Object, bool, error) {
	resource, ok := readableKinds[ref.Kind]
	if !ok {
		return Object{}, false, fmt.Errorf("kind %q is not readable by the scenario engine", ref.Kind)
	}
	path := objectPath(resource, ref)
	if ref.Kind == "Namespace" {
		path = "/api/v1/namespaces/" + url.PathEscape(ref.Name)
	}
	status, raw, err := c.do(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return Object{}, false, err
	}
	switch {
	case status == http.StatusNotFound:
		return Object{}, false, nil
	case status != http.StatusOK:
		return Object{}, false, statusErr(http.MethodGet, path, status)
	}
	var wire struct {
		Metadata struct {
			Name      string            `json:"name"`
			Namespace string            `json:"namespace"`
			Labels    map[string]string `json:"labels"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
		Spec map[string]any    `json:"spec"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return Object{}, false, errors.New("object response is not valid JSON")
	}
	return Object{
		Ref:    ObjectRef{Kind: ref.Kind, Namespace: wire.Metadata.Namespace, Name: wire.Metadata.Name},
		Labels: wire.Metadata.Labels,
		Data:   wire.Data,
		Spec:   wire.Spec,
	}, true, nil
}

// Create writes a new object. Only registry kinds in writableKinds may be created, and only in a namespace.
func (c *APIClient) Create(ctx context.Context, obj Object) error {
	resource, ok := writableKinds[obj.Ref.Kind]
	if !ok {
		return fmt.Errorf("kind %q may not be created by the scenario engine", obj.Ref.Kind)
	}
	if obj.Ref.Namespace == "" || obj.Ref.Name == "" {
		return errors.New("a namespace and a name are required")
	}
	body := map[string]any{
		"apiVersion": "v1",
		"kind":       obj.Ref.Kind,
		"metadata": map[string]any{
			"name":      obj.Ref.Name,
			"namespace": obj.Ref.Namespace,
			"labels":    obj.Labels,
		},
	}
	if obj.Spec != nil {
		body["spec"] = obj.Spec
	}
	if obj.Data != nil {
		body["data"] = obj.Data
	}
	path := nsPath(obj.Ref.Namespace) + "/" + resource
	status, _, err := c.do(ctx, http.MethodPost, path, "application/json", body)
	if err != nil {
		return err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return statusErr(http.MethodPost, path, status)
	}
	return nil
}

// SetData merges keys into a ConfigMap's data. An empty value removes the key (a JSON null in a merge patch).
func (c *APIClient) SetData(ctx context.Context, ref ObjectRef, data map[string]string) error {
	resource, ok := writableKinds[ref.Kind]
	if !ok || ref.Kind != "ConfigMap" {
		return fmt.Errorf("kind %q data may not be patched by the scenario engine", ref.Kind)
	}
	patch := map[string]map[string]any{"data": {}}
	for k, v := range data {
		if v == "" {
			patch["data"][k] = nil
		} else {
			patch["data"][k] = v
		}
	}
	path := objectPath(resource, ref)
	status, _, err := c.do(ctx, http.MethodPatch, path, "application/merge-patch+json", patch)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return statusErr(http.MethodPatch, path, status)
	}
	return nil
}

// Delete removes an object. A missing object is treated as already removed; the engine verifies the result.
func (c *APIClient) Delete(ctx context.Context, ref ObjectRef) error {
	resource, ok := writableKinds[ref.Kind]
	if !ok {
		return fmt.Errorf("kind %q may not be deleted by the scenario engine", ref.Kind)
	}
	if ref.Namespace == "" {
		return errors.New("a namespace is required")
	}
	path := objectPath(resource, ref)
	status, _, err := c.do(ctx, http.MethodDelete, path, "", nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound || status == http.StatusOK || status == http.StatusAccepted {
		return nil
	}
	return statusErr(http.MethodDelete, path, status)
}

// tokenMinimumTTL and tokenMaximumTTL bound a requested token lifetime, in seconds.
const (
	tokenMinimumTTL = 60
	tokenMaximumTTL = 3600
)

// IssueToken mints a short-lived token for one ServiceAccount through the TokenRequest API. The token is returned
// only to the caller that needs it for verification. It is never logged or placed in an error.
func (c *APIClient) IssueToken(ctx context.Context, namespace, serviceAccount string, ttlSeconds int64) (IssuedToken, error) {
	if !reK8sName.MatchString(namespace) || !reK8sName.MatchString(serviceAccount) {
		return IssuedToken{}, errors.New("a namespace and a ServiceAccount name are required")
	}
	if ttlSeconds < tokenMinimumTTL || ttlSeconds > tokenMaximumTTL {
		return IssuedToken{}, fmt.Errorf("token lifetime must be between %d and %d seconds", tokenMinimumTTL, tokenMaximumTTL)
	}
	path := "/api/v1/namespaces/" + namespace + "/serviceaccounts/" + serviceAccount + "/token"
	body := map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenRequest",
		"spec":       map[string]any{"expirationSeconds": ttlSeconds},
	}
	status, raw, err := c.do(ctx, http.MethodPost, path, "application/json", body)
	if err != nil {
		return IssuedToken{}, err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return IssuedToken{}, statusErr(http.MethodPost, path, status)
	}
	var resp struct {
		Status struct {
			Token               string    `json:"token"`
			ExpirationTimestamp time.Time `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil || resp.Status.Token == "" {
		return IssuedToken{}, errors.New("TokenRequest response did not contain a token")
	}
	return IssuedToken{Token: []byte(resp.Status.Token), Expires: resp.Status.ExpirationTimestamp}, nil
}

// IdentityWithToken returns the username a token authenticates as, using SelfSubjectReview with that token alone.
func (c *APIClient) IdentityWithToken(ctx context.Context, token []byte) (string, error) {
	const path = "/apis/authentication.k8s.io/v1/selfsubjectreviews"
	body := map[string]string{"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"}
	status, raw, err := c.doAs(ctx, string(token), http.MethodPost, path, "application/json", body)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return "", statusErr(http.MethodPost, path, status)
	}
	var review struct {
		Status struct {
			UserInfo struct {
				Username string `json:"username"`
			} `json:"userInfo"`
		} `json:"status"`
	}
	if err := json.Unmarshal(raw, &review); err != nil {
		return "", errors.New("SelfSubjectReview response is not valid JSON")
	}
	return review.Status.UserInfo.Username, nil
}
