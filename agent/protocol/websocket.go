package protocol

import (
	"encoding/json"
	"fmt"
	"net/http"
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
// handshake, using the default dialer (no custom proxy handling). Shared by
// the real agent and loadgen -- the single network-calling implementation of
// the WS connect step. Reconnect timing is the caller's concern (the real
// agent and loadgen each retry differently), so this makes exactly one
// connection attempt and returns.
func DialAgentWS(serverURL, agentID, agentSecret string) (*websocket.Conn, error) {
	return DialAgentWSWithDialer(serverURL, agentID, agentSecret, websocket.DefaultDialer)
}

// DialAgentWSWithDialer is DialAgentWS with an explicit *websocket.Dialer --
// the real agent uses this with a proxy-aware NetDialContext (see
// agent/proxyauth.go's proxyAwareNetDialContext) and, once enrolled via
// mTLS, dialer.TLSClientConfig already carrying the agent's client
// certificate (set by the caller before this function runs — see
// agent/agent.go's connectWS). loadgen and every other caller keeps using
// DialAgentWS with the zero-value dialer, unaffected by this addition.
func DialAgentWSWithDialer(serverURL, agentID, agentSecret string, dialer *websocket.Dialer) (*websocket.Conn, error) {
	rawURL := strings.Replace(serverURL, "http://", "ws://", 1)
	rawURL = strings.Replace(rawURL, "https://", "wss://", 1)

	u, err := url.Parse(rawURL + "/ws/agent")
	if err != nil {
		return nil, fmt.Errorf("invalid WS URL: %w", err)
	}
	q := u.Query()
	q.Set("agentId", agentID)
	u.RawQuery = q.Encode()

	// agentSecret goes on the handshake request as a header, never the URL
	// query string -- a query string gets logged verbatim by proxies, load
	// balancers, and server access logs along the whole network path.
	// gorilla's Dial supports request headers on the handshake for exactly
	// this reason.
	var reqHeader http.Header
	if agentSecret != "" {
		reqHeader = http.Header{"X-Agent-Token": []string{agentSecret}}
	}

	conn, _, err := dialer.Dial(u.String(), reqHeader)
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
