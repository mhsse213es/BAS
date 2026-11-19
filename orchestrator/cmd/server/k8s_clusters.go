package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/api"
	"github.com/audspect/bas/internal/db"
)

// buildK8sClusterService returns the Kubernetes service with the cluster registry attached. It is built even when the
// scenario engine is not configured, so clusters can be registered and listed. Runs still need the engine.
//
//	KUBE_CLUSTER_CREDENTIALS_DIR  directory holding <display name>.token (read-only bearer token, required to list
//	                              namespaces) and optional <display name>.ca (PEM). Read per request, never logged,
//	                              never stored in the database.
func buildK8sClusterService(pool *pgxpool.Pool) *api.K8sScenarioService {
	svc := buildK8sScenarioService(pool)
	if svc == nil {
		svc = &api.K8sScenarioService{}
	}
	svc.Registry = db.NewK8sClusterStore(pool)
	svc.Audit = db.NewK8sScenarioAudit(pool)
	svc.Authorizations = db.NewK8sAuthorizationStore(pool)
	svc.Credentials = clusterCredentialsFromDir(strings.TrimSpace(os.Getenv("KUBE_CLUSTER_CREDENTIALS_DIR")))
	return svc
}

// clusterCredentialsFromDir reads a cluster's token and CA from the directory. A display name that could be read as a
// path is refused, and a missing token means the cluster has no credential.
func clusterCredentialsFromDir(dir string) api.K8sClusterCredentials {
	return func(displayName string) (string, []byte, error) {
		if dir == "" {
			return "", nil, api.ErrK8sClusterNoCredential
		}
		if strings.ContainsAny(displayName, `/\`) || strings.Contains(displayName, "..") || displayName == "" {
			return "", nil, api.ErrK8sClusterNoCredential
		}
		tokenPath := filepath.Join(dir, displayName+".token")
		raw, err := os.ReadFile(tokenPath)
		if errors.Is(err, os.ErrNotExist) {
			return "", nil, api.ErrK8sClusterNoCredential
		}
		if err != nil {
			return "", nil, err
		}
		token := strings.TrimSpace(string(raw))
		if token == "" {
			return "", nil, api.ErrK8sClusterNoCredential
		}
		var ca []byte
		caPath := filepath.Join(dir, displayName+".ca")
		if b, err := os.ReadFile(caPath); err == nil {
			ca = b
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", nil, err
		}
		return token, ca, nil
	}
}
