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

// netProbeWaitLimit bounds how long one probe pod may run.
const netProbeWaitLimit = 3 * time.Minute

// netProbePollInterval is how often a running probe pod is checked.
const netProbePollInterval = 2 * time.Second

// NetProbeKubeClient implements NetProbeClient against the API server. It creates and deletes pods, which changes the
// cluster. It is used only for lab-class clusters.
type NetProbeKubeClient struct {
	server string
	token  string
	http   *http.Client
}

// NewNetProbeKubeClient validates the configuration. The server must be https and a token is required.
func NewNetProbeKubeClient(server, token string, caPEM []byte) (*NetProbeKubeClient, error) {
	u, err := url.Parse(server)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("the API server must be an https URL")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("a token is required for network probes")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("the cluster CA PEM could not be parsed")
		}
		tlsCfg.RootCAs = pool
	}
	return &NetProbeKubeClient{server: strings.TrimRight(server, "/"), token: token,
		http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}}, nil
}

func (c *NetProbeKubeClient) send(ctx context.Context, method, path string, body any) (int, []byte, error) {
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
	return resp.StatusCode, data, err
}

func podPath(namespace, name string) string {
	return "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods/" + url.PathEscape(name)
}

// CreatePod creates the probe pod.
func (c *NetProbeKubeClient) CreatePod(ctx context.Context, namespace string, pod map[string]any) error {
	status, raw, err := c.send(ctx, http.MethodPost, "/api/v1/namespaces/"+url.PathEscape(namespace)+"/pods", pod)
	if err != nil {
		return err
	}
	if status == http.StatusCreated || status == http.StatusOK {
		return nil
	}
	return fmt.Errorf("create pod: HTTP %d: %s", status, strings.TrimSpace(string(raw)))
}

// WaitPod polls until the pod has finished, and returns its exit code.
func (c *NetProbeKubeClient) WaitPod(ctx context.Context, namespace, name string) (PodState, error) {
	wctx, cancel := context.WithTimeout(ctx, netProbeWaitLimit)
	defer cancel()
	for {
		status, raw, err := c.send(wctx, http.MethodGet, podPath(namespace, name), nil)
		if err != nil {
			return PodState{}, err
		}
		if status != http.StatusOK {
			return PodState{}, fmt.Errorf("read pod: HTTP %d", status)
		}
		var pod struct {
			Status struct {
				Phase             string `json:"phase"`
				ContainerStatuses []struct {
					State struct {
						Terminated *struct {
							ExitCode int `json:"exitCode"`
						} `json:"terminated"`
					} `json:"state"`
				} `json:"containerStatuses"`
			} `json:"status"`
		}
		if err := json.Unmarshal(raw, &pod); err != nil {
			return PodState{}, errors.New("pod response is not valid JSON")
		}
		if pod.Status.Phase == "Succeeded" || pod.Status.Phase == "Failed" {
			ps := PodState{Phase: pod.Status.Phase}
			if len(pod.Status.ContainerStatuses) > 0 && pod.Status.ContainerStatuses[0].State.Terminated != nil {
				ps.ExitCode = pod.Status.ContainerStatuses[0].State.Terminated.ExitCode
			}
			return ps, nil
		}
		select {
		case <-wctx.Done():
			return PodState{}, fmt.Errorf("probe pod did not finish: %w", wctx.Err())
		case <-time.After(netProbePollInterval):
		}
	}
}

// PodLogs returns the probe container's log.
func (c *NetProbeKubeClient) PodLogs(ctx context.Context, namespace, name string) (string, error) {
	status, raw, err := c.send(ctx, http.MethodGet, podPath(namespace, name)+"/log?container=probe", nil)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("read pod logs: HTTP %d", status)
	}
	return string(raw), nil
}

// DeletePod removes the probe pod. A pod that is already gone counts as removed.
func (c *NetProbeKubeClient) DeletePod(ctx context.Context, namespace, name string) error {
	status, raw, err := c.send(ctx, http.MethodDelete, podPath(namespace, name), nil)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusOK, http.StatusAccepted, http.StatusNotFound:
		return nil
	}
	return fmt.Errorf("delete pod: HTTP %d: %s", status, strings.TrimSpace(string(raw)))
}

// PodExists reports whether the pod is still present.
func (c *NetProbeKubeClient) PodExists(ctx context.Context, namespace, name string) (bool, error) {
	status, _, err := c.send(ctx, http.MethodGet, podPath(namespace, name), nil)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	}
	return false, fmt.Errorf("read pod: HTTP %d", status)
}
