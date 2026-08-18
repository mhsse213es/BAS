package main

import (
	"encoding/json"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	wsReconnectDelay = 5 * time.Second
	wsPongWait       = 60 * time.Second
	wsWriteWait      = 10 * time.Second
)

// buildWSURL mirrors agent/agent.go's connectWS URL construction exactly --
// same query param names (agentId, agentSecret), same http->ws / https->wss
// scheme swap, so the orchestrator's WS handshake auth sees an identical
// request shape regardless of which agent connected.
func buildWSURL(cfg Config, agentID string) string {
	raw := strings.Replace(cfg.ServerURL, "http://", "ws://", 1)
	raw = strings.Replace(raw, "https://", "wss://", 1)
	u, err := url.Parse(raw + "/ws/agent")
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("agentId", agentID)
	if cfg.AgentSecret != "" {
		q.Set("agentSecret", cfg.AgentSecret)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// connectWS blocks forever, reconnecting on any failure. Phase 1 has no
// scenario/simulate command handlers yet -- an inbound WSMessage is parsed
// only far enough to log its type, proving the wire format round-trips
// correctly; actual command dispatch is Phase 2/3 scope once there's
// something on the legacy agent capable of executing a command.
func connectWS(cfg Config, id Identity) {
	wsURL := buildWSURL(cfg, id.AgentID)
	for {
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			log.Printf("[!] WS connect failed: %v -- retry in 5s", err)
			time.Sleep(wsReconnectDelay)
			continue
		}
		log.Printf("[+] WS connected: %s", wsURL)

		conn.SetReadDeadline(time.Now().Add(wsPongWait))
		conn.SetPingHandler(func(appData string) error {
			conn.SetReadDeadline(time.Now().Add(wsPongWait))
			err := conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(wsWriteWait))
			if err == websocket.ErrCloseSent {
				return nil
			}
			return err
		})

		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				log.Printf("[!] WS read: %v -- reconnecting", err)
				conn.Close()
				break
			}
			conn.SetReadDeadline(time.Now().Add(wsPongWait))
			var msg struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(data, &msg); err == nil {
				log.Printf("[*] WS message received: type=%s (no handler yet -- Phase 1)", msg.Type)
			}
		}
	}
}
