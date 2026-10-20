package protocol

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// WebSocket is the WebSocket adapter for the handshake (RFC 6455, section 4). A scenario sends the
// opening GET with the upgrade headers, and the adapter refuses a handshake that is not well formed,
// so a scenario cannot send one a client would never produce. Frames after the handshake are read
// from the connection by the lab's route, not by the runner.
type WebSocket struct{}

func init() { Register(WebSocket{}) }

// Name is the protocol name.
func (WebSocket) Name() string { return "websocket" }

// Validate checks the body of a handshake. A handshake has no body.
func (WebSocket) Validate(body string) error {
	if strings.TrimSpace(body) != "" {
		return errors.New("websocket handshake has no body")
	}
	return nil
}

// ValidateHandshake checks an opening handshake: GET, the upgrade headers, version 13, a 16-byte
// base64 key, and an Origin, which browsers always send and which the origin check depends on.
func (WebSocket) ValidateHandshake(method string, headers map[string]string) error {
	if method != "GET" {
		return fmt.Errorf("websocket handshake must be GET, got %s", method)
	}
	h := lowerKeys(headers)
	if h["upgrade"] != "websocket" {
		return errors.New("websocket handshake needs Upgrade: websocket")
	}
	if !containsToken(h["connection"], "upgrade") {
		return errors.New("websocket handshake needs Connection: Upgrade")
	}
	if h["sec-websocket-version"] != "13" {
		return errors.New("websocket handshake needs Sec-WebSocket-Version: 13")
	}
	key, err := base64.StdEncoding.DecodeString(h["sec-websocket-key"])
	if err != nil || len(key) != 16 {
		return errors.New("websocket handshake needs Sec-WebSocket-Key, base64 of 16 bytes")
	}
	if h["origin"] == "" {
		return errors.New("websocket handshake needs an Origin header")
	}
	return nil
}

func lowerKeys(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[strings.ToLower(k)] = v
	}
	return out
}

// containsToken reports whether a comma-separated header value contains the token, ignoring case.
func containsToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}
