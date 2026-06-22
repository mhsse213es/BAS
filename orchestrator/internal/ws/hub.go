package ws

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

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
}

type conn struct {
	ws   *websocket.Conn
	send chan []byte
}

// NewHub creates a ready-to-use Hub.
func NewHub() *Hub {
	return &Hub{agents: make(map[string]*conn)}
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
func (h *Hub) SendToAgent(agentID string, msg models.WSMessage) bool {
	h.mu.RLock()
	c, ok := h.agents[agentID]
	h.mu.RUnlock()
	if !ok {
		return false
	}
	b, _ := json.Marshal(msg)
	select {
	case c.send <- b:
		return true
	default:
		return false
	}
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
				return
			}
		case <-ticker.C:
			c.ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.ws.WriteMessage(websocket.PingMessage, nil); err != nil {
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
