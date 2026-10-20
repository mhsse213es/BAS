package lab

// WebSocket route for Phase 28 (AUTHN-011): GET /ws/orders performs an RFC 6455 handshake, then sends
// one unmasked text frame carrying the order event for ORD-2001 and closes. The vulnerable build
// accepts any Origin and any credential (LAB-AUTHN-WS-001). The fixed build requires the allowed
// Origin, a valid bearer token, and ownership of the order, and refuses otherwise with 403 before
// the upgrade, so no frame is sent.

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

// wsAllowedOrigin is the only browser origin the fixed build accepts.
const wsAllowedOrigin = "https://app.audspect.example"

// wsGUID is the fixed GUID of RFC 6455 section 1.3, used to compute the accept key.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func (s *Server) registerWebSocket(mux *http.ServeMux) {
	mux.HandleFunc("GET /ws/orders", s.wsOrders)
}

// wsFlaws lists the WebSocket flaws.
func wsFlaws() []Flaw {
	return []Flaw{
		{ID: "LAB-AUTHN-WS-001", ScenarioID: "API-BAS-AUTHN-011", Description: "GET /ws/orders completes the handshake for any Origin and any credential, and streams the order event with its protected values.", Oracle: "protected values of the order appear in a frame sent to an unauthenticated foreign-origin client"},
	}
}

func (s *Server) wsOrders(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	o, found := s.orders["ORD-2001"]
	var body map[string]any
	if found {
		if s.vulnerable() {
			body = orderBody(o)
		}
	}
	s.mu.Unlock()

	if !s.vulnerable() {
		if r.Header.Get("Origin") != wsAllowedOrigin {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin not allowed"})
			return
		}
		caller, st := s.identify(r)
		if st != authOK {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "credential required"})
			return
		}
		s.mu.Lock()
		owned := found && o.OwnerID == caller
		if owned {
			body = publicView(o)
		}
		s.mu.Unlock()
		if !owned {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "order not owned by the caller"})
			return
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "upgrade unsupported"})
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	payload, err := json.Marshal(map[string]any{"event": "order.updated", "order": body})
	if err != nil {
		return
	}
	accept := wsAcceptKey(r.Header.Get("Sec-WebSocket-Key"))
	rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	rw.WriteString("Upgrade: websocket\r\n")
	rw.WriteString("Connection: Upgrade\r\n")
	rw.WriteString("Sec-WebSocket-Accept: " + accept + "\r\n\r\n")
	rw.Write(textFrame(payload))
	rw.Flush()
}

// wsAcceptKey is the Sec-WebSocket-Accept value for a client key (RFC 6455 section 4.2.2). SHA-1 is
// required by the protocol here; it is not used for any security purpose.
func wsAcceptKey(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// textFrame encodes one final, unmasked text frame. Server frames are never masked (RFC 6455 5.1).
func textFrame(payload []byte) []byte {
	n := len(payload)
	out := []byte{0x81}
	switch {
	case n < 126:
		out = append(out, byte(n))
	case n <= 0xFFFF:
		out = append(out, 126, byte(n>>8), byte(n))
	default:
		out = append(out, 127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, payload...)
}
