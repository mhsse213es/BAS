package protocol

import "testing"

func validHandshake() map[string]string {
	return map[string]string{
		"Upgrade":               "websocket",
		"Connection":            "Upgrade",
		"Sec-WebSocket-Version": "13",
		"Sec-WebSocket-Key":     "dGhlIHNhbXBsZSBub25jZQ==",
		"Origin":                "https://app.audspect.example",
	}
}

func TestWebSocketAcceptsWellFormedHandshake(t *testing.T) {
	if err := (WebSocket{}).ValidateHandshake("GET", validHandshake()); err != nil {
		t.Fatalf("well-formed handshake refused: %v", err)
	}
}

func TestWebSocketRefusesMalformedHandshake(t *testing.T) {
	mutate := map[string]func(h map[string]string){
		"no upgrade header":   func(h map[string]string) { delete(h, "Upgrade") },
		"wrong upgrade":       func(h map[string]string) { h["Upgrade"] = "h2c" },
		"no connection token": func(h map[string]string) { h["Connection"] = "keep-alive" },
		"wrong version":       func(h map[string]string) { h["Sec-WebSocket-Version"] = "8" },
		"short key":           func(h map[string]string) { h["Sec-WebSocket-Key"] = "c2hvcnQ=" },
		"no origin":           func(h map[string]string) { delete(h, "Origin") },
	}
	for name, f := range mutate {
		t.Run(name, func(t *testing.T) {
			h := validHandshake()
			f(h)
			if err := (WebSocket{}).ValidateHandshake("GET", h); err == nil {
				t.Fatalf("%s accepted, want refusal", name)
			}
		})
	}
	if err := (WebSocket{}).ValidateHandshake("POST", validHandshake()); err == nil {
		t.Fatal("POST handshake accepted, want refusal")
	}
}

func TestWebSocketHandshakeHasNoBody(t *testing.T) {
	if err := (WebSocket{}).Validate(""); err != nil {
		t.Fatalf("empty body refused: %v", err)
	}
	if err := (WebSocket{}).Validate("data"); err == nil {
		t.Fatal("handshake with a body accepted")
	}
}

func TestWebSocketIsRegistered(t *testing.T) {
	if !Supported("websocket") {
		t.Fatal("websocket has an adapter but Supported reports false")
	}
}
