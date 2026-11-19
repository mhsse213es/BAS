package api

import (
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/pki"

	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
)

// WithPKIDir tells the handler where the CA files live, so it can read a prepared CA rotation (audit F-09).
func (h *Handler) WithPKIDir(dir string) *Handler {
	h.pkiDir = dir
	return h
}

// rotationState returns the rotation state, or writes the error response and returns ok=false.
func (h *Handler) rotationState(w http.ResponseWriter) (pki.RotationState, bool) {
	if h.pkiDir == "" {
		jsonError(w, "CA rotation is not available: the PKI directory is not configured", http.StatusServiceUnavailable)
		return "", false
	}
	state, err := pki.RotationStatus(h.pkiDir)
	if err != nil {
		jsonError(w, err.Error(), http.StatusConflict)
		return "", false
	}
	return state, true
}

func pemFingerprint(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return "", os.ErrInvalid
	}
	s := sha256.Sum256(blk.Bytes)
	return hex.EncodeToString(s[:]), nil
}

// POST /api/ca-rotation/distribute -- sends the prepared next CA root, with the cross-certificate that the
// current CA signed for it, to every connected agent as a signed command. Only while a rotation is
// "prepared"; it changes no issuance and no server trust. The agent accepts the root only if the CA it
// already pins vouches for it. Safe to repeat: agents that already trust the root ignore it. Admin-only.
func (h *Handler) DistributeCARoot(w http.ResponseWriter, r *http.Request) {
	state, ok := h.rotationState(w)
	if !ok {
		return
	}
	if state != pki.RotationPrepared {
		jsonError(w, "no prepared CA rotation to distribute (state: "+string(state)+")", http.StatusConflict)
		return
	}
	root, err := os.ReadFile(filepath.Join(h.pkiDir, "next-ca-cert.pem"))
	if err != nil {
		jsonError(w, "read the prepared CA root: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cross, err := os.ReadFile(filepath.Join(h.pkiDir, "next-ca-cross.pem"))
	if err != nil {
		jsonError(w, "read the cross-certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rows, err := h.db.Query(r.Context(),
		`SELECT agent_id FROM agents WHERE COALESCE(state,'active') NOT IN ('revoked','uninstalling','uninstalled')`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()

	sent := 0
	notConnected := []string{}
	for _, id := range ids {
		if h.hub.SendToAgent(id, models.WSMessage{
			Type:    models.MsgCommandTrustCA,
			AgentID: id,
			Data:    map[string]string{"rootPem": string(root), "crossPem": string(cross)},
		}) {
			sent++
		} else {
			notConnected = append(notConnected, id)
		}
	}
	h.auditLog(r, "ca_rotation.distribute", "ca_rotation",
		map[string]any{"sent": sent, "notConnected": len(notConnected)}, "ok")
	respond(w, map[string]any{"sent": sent, "notConnected": notConnected})
}

// GET /api/ca-rotation/status -- the rotation state and, while one is prepared, how many agents already trust
// the new root. readyToPromote is true only when every agent that can still connect reports it, so the
// issuing CA is never switched ahead of the fleet. Revoked and uninstalling agents are not counted.
func (h *Handler) CARotationStatus(w http.ResponseWriter, r *http.Request) {
	state, ok := h.rotationState(w)
	if !ok {
		return
	}
	resp := map[string]any{"state": string(state), "checkedAt": time.Now().UTC()}
	if state == pki.RotationPrepared {
		fp, err := pemFingerprint(filepath.Join(h.pkiDir, "next-ca-cert.pem"))
		if err != nil {
			jsonError(w, "read the prepared CA root: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rows, err := h.db.Query(r.Context(), `
			SELECT agent_id, COALESCE(trusted_root_fps, '[]'::jsonb) ? $1
			  FROM agents
			 WHERE COALESCE(state,'active') NOT IN ('revoked','uninstalling','uninstalled')
			 ORDER BY agent_id`, fp)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		pending := []string{}
		total, have := 0, 0
		for rows.Next() {
			var id string
			var has bool
			if rows.Scan(&id, &has) != nil {
				continue
			}
			total++
			if has {
				have++
			} else {
				pending = append(pending, id)
			}
		}
		resp["newRootFingerprint"] = fp
		resp["agentsTotal"] = total
		resp["agentsWithNewRoot"] = have
		resp["agentsPending"] = pending
		resp["readyToPromote"] = total > 0 && have == total
	}
	respond(w, resp)
}
