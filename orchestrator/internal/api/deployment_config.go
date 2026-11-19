package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/audspect/bas/internal/deployconfig"
)

// GET /api/config/deployment-config -- the signed deployment.json that
// accompanies the Windows agent MSI. It carries no secret. Admin-gated like
// /api/config/connection, because the fingerprint an operator must pin comes
// from the same authenticated channel (deploymentSigningFingerprint there);
// the file alone proves nothing since it embeds its own signing certificate.
func (h *Handler) GetDeploymentConfig(w http.ResponseWriter, r *http.Request) {
	if h.signingKey == nil {
		jsonError(w, "no signing key is configured on this server", http.StatusServiceUnavailable)
		return
	}
	cfg := deployconfig.Config{
		ServerURL:  "https://" + requestHost(r) + ":" + portOrDefault(h.advertisedMTLSPort, "9443"),
		EnrollPort: portOrDefault(h.advertisedEnrollPort, "9444"),
		IssuedAt:   time.Now().UTC(),
	}
	if h.pki != nil {
		cfg.CARootPEM = string(h.pki.RootCertPEM())
	}
	env, err := deployconfig.Build(h.signingKey, cfg)
	if err != nil {
		jsonError(w, "could not build the deployment configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="deployment.json"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(env)
}

func portOrDefault(p int, def string) string {
	if p <= 0 {
		return def
	}
	return strconv.Itoa(p)
}
