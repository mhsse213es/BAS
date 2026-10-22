// orchestrator/internal/api/agent_install_script.go
package api

import (
	_ "embed"
	"net/http"
)

// installAgentLinuxScript is the Linux agent installer. It is served unauthenticated so the
// console's install command can download it on the target machine. It contains no secret.
//
//go:embed agentinstall/install-agent-linux.sh
var installAgentLinuxScript []byte

// GET /api/agent/install-script: the Linux agent installer, as a shell script.
func (h *Handler) GetAgentInstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(installAgentLinuxScript)
}
