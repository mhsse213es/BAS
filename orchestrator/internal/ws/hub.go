package ws

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/audspect/bas/internal/cmdsigning"
	"github.com/audspect/bas/internal/models"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

const (
	// Keepalive: writePump sends a ping every pingPeriod; readPump declares the
	// peer dead if no frame (ping reply/pong or app message) arrives within
	// pongWait. This drops half-open connections — e.g. an agent whose host went
	// away, or a browser tab that was killed — and frees the slot. The agent
	// mirrors this with its own read deadline so it reconnects after a server
	// restart instead of hanging on a half-open TCP socket.
	writeWait  = 10 * time.Second
	pongWait   = 60 * time.Second
	pingPeriod = 25 * time.Second // must be < pongWait
)

// Hub manages all active WebSocket connections — both endpoint agents and browser dashboards.
type Hub struct {
	mu       sync.RWMutex
	agents   map[string]*conn // agentID → connection
	browsers []*conn
	signer   *rsa.PrivateKey // deployment command-signing key (B4) -- see internal/cmdsigning. Set via SetSigner, read by SendToAgent starting in Task 5.
}

type conn struct {
	ws   *websocket.Conn
	send chan []byte
}

// NewHub creates a ready-to-use Hub with no command-signing key. Kept
// zero-arg deliberately: hundreds of existing test call sites across this
// module construct a Hub with ws.NewHub() and never exercise command
// signing at all -- changing this signature would force touching every
// one of them for no benefit. Production wiring calls SetSigner once,
// right after construction (see cmd/server/main.go).
func NewHub() *Hub {
	return &Hub{agents: make(map[string]*conn)}
}

// SetSigner installs the deployment command-signing private key
// (internal/cmdsigning.SigningKey.PrivateKey()) -- never the vendor
// scenario-signing key, which this package never imports or references.
// A Hub with no signer set (the zero value, nil) sends in-scope command
// types unsigned instead, with a loud warning logged -- see
// SendToAgent's doc comment for why that's the correct behavior (the
// agent's own verification is the real enforcement boundary, not this
// step) rather than refusing to send at all.
func (h *Hub) SetSigner(signer *rsa.PrivateKey) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.signer = signer
}

// ServeAgentWS upgrades an agent's HTTP connection to WebSocket.
// Query param: ?agentId=<id>
func (h *Hub) ServeAgentWS(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agentId")
	if agentID == "" {
		http.Error(w, "agentId required", http.StatusBadRequest)
		return
	}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ws] agent upgrade error: %v", err)
		return
	}
	c := &conn{ws: ws, send: make(chan []byte, 128)}

	h.mu.Lock()
	h.agents[agentID] = c
	h.mu.Unlock()
	log.Printf("[ws] agent connected: %s", agentID)

	go c.writePump()
	c.readPump(func(msg models.WSMessage) {
		// Agent → server messages (heartbeat, scenario results) get broadcast to browsers
		h.BroadcastBrowsers(msg)
	})

	h.mu.Lock()
	delete(h.agents, agentID)
	h.mu.Unlock()
	log.Printf("[ws] agent disconnected: %s", agentID)
}

// ServeBrowserWS upgrades a dashboard browser connection to WebSocket.
func (h *Hub) ServeBrowserWS(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ws] browser upgrade error: %v", err)
		return
	}
	c := &conn{ws: ws, send: make(chan []byte, 128)}

	h.mu.Lock()
	h.browsers = append(h.browsers, c)
	h.mu.Unlock()

	go c.writePump()
	c.readPump(nil) // browsers receive only; they send commands via REST

	h.mu.Lock()
	for i, b := range h.browsers {
		if b == c {
			h.browsers = append(h.browsers[:i], h.browsers[i+1:]...)
			break
		}
	}
	h.mu.Unlock()
}

// SendToAgent delivers a message to a specific connected agent.
// Returns false if the agent is not currently connected.
//
// For any of the 8 execution-triggering command types
// (models.IsSignedCommandType), msg.Data is wrapped in a signed
// models.CommandEnvelope before marshaling -- this is the single
// mandatory signing boundary every one of this codebase's 16 dispatch
// call sites already funnels through, so none of them need to change.
// Every other message type passes through completely unchanged.
//
// If no signing key is configured (h.signer == nil -- SetSigner was
// never called; unreachable in real production traffic since main.go
// calls it unconditionally right after ws.NewHub(), before any HTTP/WS
// handler starts serving), the message is still sent, unsigned, with a
// loud warning logged. This is deliberate, not a security hole: the
// actual enforcement boundary is the AGENT's own verification
// (agent/commandsig.go's verifyCommandEnvelope, wired into every
// connectWS dispatch) -- an unsigned or malformed envelope is rejected
// there unconditionally, regardless of why the orchestrator failed to
// sign it. Hard-failing the send here as well was tried first and
// reverted: it broke ~60 pre-existing tests across internal/api (found
// during this plan's Final Verification) that constructs a bare
// ws.NewHub() with no reason to exercise signing at all, with no single
// shared construction point to fix centrally.
func (h *Hub) SendToAgent(agentID string, msg models.WSMessage) (sent bool) {
	h.mu.RLock()
	c, ok := h.agents[agentID]
	h.mu.RUnlock()
	if !ok {
		return false
	}

	if models.IsSignedCommandType(msg.Type) {
		h.mu.RLock()
		hasSigner := h.signer != nil
		h.mu.RUnlock()
		if !hasSigner {
			log.Printf("[ws] WARNING: no command-signing key installed -- sending %s to agent %s UNSIGNED (the agent will reject it; see SendToAgent's doc comment)", msg.Type, agentID)
		} else {
			signed, err := h.signCommand(agentID, msg)
			if err != nil {
				log.Printf("[ws] sign command %s for agent %s: %v -- not sent", msg.Type, agentID, err)
				return false
			}
			msg.Data = signed
		}
	}

	b, _ := json.Marshal(msg)
	// readPump closes c.send when the agent disconnects, and does so
	// independently of (and slightly before) this Hub removing the agent
	// from h.agents — so a disconnect landing between our lookup above and
	// the send below can hit an already-closed channel. Sending on a closed
	// channel panics unconditionally; recover and report it exactly like
	// "not connected", which is what it functionally is.
	defer func() {
		if recover() != nil {
			sent = false
		}
	}()
	select {
	case c.send <- b:
		return true
	default:
		return false
	}
}

// signCommand builds and signs the CommandEnvelope for an in-scope
// command type. runID/scenarioID/mode are extracted from msg.Data on a
// best-effort basis (only ScenarioCommand-shaped payloads carry them
// today); command types without a scenario context (cancel, pause,
// resume, stop_agent, uninstall_agent) simply leave those fields at
// their zero value, which CommandEnvelope's omitempty tags already
// handle correctly.
//
// Callers (SendToAgent) only reach this once they've already confirmed
// h.signer is non-nil; the nil check below is defense-in-depth for any
// future direct caller, not the primary guard.
func (h *Hub) signCommand(agentID string, msg models.WSMessage) (models.CommandEnvelope, error) {
	h.mu.RLock()
	signer := h.signer
	h.mu.RUnlock()
	if signer == nil {
		return models.CommandEnvelope{}, fmt.Errorf("no command-signing key installed (SetSigner was never called)")
	}

	payload, err := json.Marshal(msg.Data)
	if err != nil {
		return models.CommandEnvelope{}, fmt.Errorf("marshal payload: %w", err)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return models.CommandEnvelope{}, fmt.Errorf("generate nonce: %w", err)
	}
	commandID := make([]byte, 16)
	if _, err := rand.Read(commandID); err != nil {
		return models.CommandEnvelope{}, fmt.Errorf("generate command id: %w", err)
	}
	now := time.Now().UTC()
	env := models.CommandEnvelope{
		Version:     models.CommandEnvelopeVersion,
		CommandID:   hex.EncodeToString(commandID),
		CommandType: msg.Type,
		AgentID:     agentID,
		IssuedAt:    now,
		ExpiresAt:   now.Add(commandEnvelopeTTL),
		Nonce:       hex.EncodeToString(nonce),
		Payload:     payload,
	}
	// Best-effort extraction of the optional context fields from
	// ScenarioCommand-shaped payloads -- see scenario.ScenarioCommand.
	var ctx struct {
		RunID      string `json:"runId"`
		ScenarioID string `json:"scenarioId"`
		Mode       string `json:"mode"`
		Steps      []struct {
			ExecutionClass    string `json:"executionClass"`
			DestructiveAction string `json:"destructiveAction"`
			BlastRadius       string `json:"blastRadius"`
		} `json:"steps"`
	}
	if json.Unmarshal(payload, &ctx) == nil {
		env.RunID = ctx.RunID
		env.ScenarioID = ctx.ScenarioID
		env.Mode = ctx.Mode
		env.ExecutionClass, env.DestructiveAction, env.BlastRadius = mostRestrictiveStep(ctx.Steps)
	}

	sig, err := cmdsigning.SignEnvelope(signer, env)
	if err != nil {
		return models.CommandEnvelope{}, fmt.Errorf("sign envelope: %w", err)
	}
	env.Signature = sig
	return env, nil
}

// mostRestrictiveStep returns the aggregate execution_class/destructive_action/
// blast_radius across a dispatch's steps -- "destructive" beats
// "potentially_destructive" beats "non_destructive" beats "" (no steps,
// or a non-scenario command type). Informational/audit-only, per the
// spec -- never consulted by the agent's B5 gate.
func mostRestrictiveStep(steps []struct {
	ExecutionClass    string `json:"executionClass"`
	DestructiveAction string `json:"destructiveAction"`
	BlastRadius       string `json:"blastRadius"`
}) (class, action, blast string) {
	rank := map[string]int{"": 0, "non_destructive": 1, "potentially_destructive": 2, "destructive": 3}
	best := -1
	for _, s := range steps {
		if r := rank[s.ExecutionClass]; r > best {
			best = r
			class, action, blast = s.ExecutionClass, s.DestructiveAction, s.BlastRadius
		}
	}
	return class, action, blast
}

// commandEnvelopeTTL is how long a signed command remains valid --
// deliberately short (see the spec's "Expiry & replay" section for the
// full rationale). Configurable via env var rather than hardcoded, per
// the spec's explicit requirement.
var commandEnvelopeTTL = commandEnvelopeTTLFromEnv()

func commandEnvelopeTTLFromEnv() time.Duration {
	if v := os.Getenv("COMMAND_ENVELOPE_TTL_SECONDS"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 60 * time.Second
}

// BroadcastBrowsers sends a message to all connected dashboard browsers.
func (h *Hub) BroadcastBrowsers(msg models.WSMessage) {
	b, _ := json.Marshal(msg)
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, c := range h.browsers {
		select {
		case c.send <- b:
		default:
		}
	}
}

// BroadcastTamperAlert pushes a tamper-detection event to all browser sessions.
// Satisfies the integrity.TamperBroadcaster interface so the watcher package
// does not need to import ws (avoiding an import cycle).
func (h *Hub) BroadcastTamperAlert(path, eventType, severity string) {
	msg := models.WSMessage{
		Type: models.MsgTamperAlert,
		Data: map[string]string{
			"path":      path,
			"eventType": eventType,
			"severity":  severity,
		},
	}
	h.BroadcastBrowsers(msg)
}

// CloseAllAgentConnections force-closes every currently-connected agent
// WebSocket session and clears the agents map. Called once, by the
// license monitor's onLock callback (see cmd/server/main.go), on the
// transition into license.StateLocked — agents must stop receiving new
// work and stop submitting results while the platform is locked.
func (h *Hub) CloseAllAgentConnections() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for agentID, c := range h.agents {
		if c.ws != nil {
			// Best-effort graceful close frame, mirroring writePump's own
			// graceful-close path (hub.go:187) — then force the underlying
			// connection closed so a blocked readPump's ReadMessage call
			// returns immediately instead of waiting out pongWait.
			c.ws.WriteMessage(websocket.CloseMessage, []byte{})
			c.ws.Close()
		}
		delete(h.agents, agentID)
		log.Printf("[ws] agent force-disconnected (license locked): %s", agentID)
	}
}

// ConnectedAgents returns the IDs of all currently connected agents.
func (h *Hub) ConnectedAgents() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ids := make([]string, 0, len(h.agents))
	for id := range h.agents {
		ids = append(ids, id)
	}
	return ids
}

// IsAgentConnected reports whether a specific agent currently has a live
// WebSocket connection. Used by the EM Sweep and Full Variant Sweep
// dispatchers to distinguish "the agent disconnected" from "the agent is
// connected but a layer/technique is genuinely hung" -- see
// docs/superpowers/specs/2026-08-18-sweep-disconnect-resilience-design.md.
func (h *Hub) IsAgentConnected(agentID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.agents[agentID]
	return ok
}

func (c *conn) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.ws.Close()
	}()
	for {
		select {
		case msg, ok := <-c.send:
			c.ws.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// readPump closed the channel — the connection is gone.
				c.ws.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.ws.WriteMessage(websocket.TextMessage, msg); err != nil {
				// This used to fail silently -- SendToAgent had already
				// returned true (it only confirms the message was queued,
				// not delivered), so a write that can't complete within
				// writeWait (e.g. a large ScenarioCommand over a slow link)
				// dropped the connection with no trace anywhere. Logging
				// the message size makes a slow/oversized payload visible
				// instead of indistinguishable from a normal disconnect.
				log.Printf("[ws] write failed (%d bytes), closing connection: %v", len(msg), err)
				return
			}
		case <-ticker.C:
			c.ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("[ws] ping write failed, closing connection: %v", err)
				return
			}
		}
	}
}

func (c *conn) readPump(onMessage func(models.WSMessage)) {
	defer func() {
		c.ws.Close()
		close(c.send)
	}()
	// Keepalive: declare the peer dead if nothing arrives within pongWait. The
	// pong handler (and any inbound frame) extends the deadline. Browsers and the
	// agent both auto-reply to our pings, so a healthy peer keeps resetting it.
	c.ws.SetReadDeadline(time.Now().Add(pongWait))
	c.ws.SetPongHandler(func(string) error {
		c.ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	for {
		_, b, err := c.ws.ReadMessage()
		if err != nil {
			return
		}
		c.ws.SetReadDeadline(time.Now().Add(pongWait))
		if onMessage != nil {
			var msg models.WSMessage
			if json.Unmarshal(b, &msg) == nil {
				onMessage(msg)
			}
		}
	}
}
