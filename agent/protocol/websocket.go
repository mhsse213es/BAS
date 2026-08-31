package protocol

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// wsPongWait is how long the connection may go without a server ping
	// before it's considered dead. Both the real agent and loadgen must
	// agree on this -- it's a protocol-level keepalive contract, not a
	// per-caller tuning knob.
	wsPongWait = 60 * time.Second
	// wsWriteWait bounds how long writing a pong control frame may take.
	wsWriteWait = 10 * time.Second
)

// DialAgentWS connects to /ws/agent and arms the ping/pong keepalive
// handshake. Shared by the real agent and loadgen -- the single
// network-calling implementation of the WS connect step. Reconnect timing
// is the caller's concern (the real agent and loadgen each retry
// differently), so this makes exactly one connection attempt and returns.
func DialAgentWS(serverURL, agentID, agentSecret string) (*websocket.Conn, error) {
	rawURL := strings.Replace(serverURL, "http://", "ws://", 1)
	rawURL = strings.Replace(rawURL, "https://", "wss://", 1)

	u, err := url.Parse(rawURL + "/ws/agent")
	if err != nil {
		return nil, fmt.Errorf("invalid WS URL: %w", err)
	}
	q := u.Query()
	q.Set("agentId", agentID)
	if agentSecret != "" {
		q.Set("agentSecret", agentSecret)
	}
	u.RawQuery = q.Encode()

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("WS dial: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(wsPongWait))
	conn.SetPingHandler(func(appData string) error {
		conn.SetReadDeadline(time.Now().Add(wsPongWait))
		err := conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(wsWriteWait))
		if err == websocket.ErrCloseSent {
			return nil
		}
		return err
	})
	return conn, nil
}

// ReadMessage reads and decodes one WSMessage off conn, extending the read
// deadline on every inbound frame (any frame is proof of life). Shared by
// the real agent and loadgen.
func ReadMessage(conn *websocket.Conn) (WSMessage, error) {
	var msg WSMessage
	_, data, err := conn.ReadMessage()
	if err != nil {
		return msg, err
	}
	conn.SetReadDeadline(time.Now().Add(wsPongWait))
	if err := json.Unmarshal(data, &msg); err != nil {
		return msg, fmt.Errorf("decode WSMessage: %w", err)
	}
	return msg, nil
}
