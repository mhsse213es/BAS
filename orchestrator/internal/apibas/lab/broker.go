package lab

// Async broker route for Phase 28. POST /broker/topics/{topic}/publish accepts an event. Two topics
// have separate policies:
//   - orders.events requires an HMAC-SHA256 signature over the body. The vulnerable build does not
//     verify it (LAB-INTEG-EVENT-001), so an altered event is processed and changes the order's status.
//     The fixed build verifies it and refuses an altered event with 403.
//   - orders.retries needs no signature. Each publisher may have five accepted publishes per topic.
//     The vulnerable build has no quota (LAB-ABUSE-QUEUE-001). The fixed build returns 429 beyond it.
//
// brokerSigningKey is a lab fixture constant, not a secret. It exists only so that the signed
// baseline in INTEG-010 verifies in the fixed build, and it is recorded in the QA log.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

const brokerSigningKey = "audspect-lab-event-key-v1"

// brokerQuota is the number of accepted publishes per publisher per topic in the fixed build.
const brokerQuota = 5

func (s *Server) registerBroker(mux *http.ServeMux) {
	mux.HandleFunc("POST /broker/topics/{topic}/publish", s.brokerPublish)
}

// brokerFlaws lists the broker flaws.
func brokerFlaws() []Flaw {
	return []Flaw{
		{ID: "LAB-INTEG-EVENT-001", ScenarioID: "API-BAS-INTEG-010", Description: "POST /broker/topics/orders.events/publish does not verify the event signature, so an altered event is processed.", Oracle: "the order's status changes because of an event whose payload was altered after signing"},
		{ID: "LAB-ABUSE-QUEUE-001", ScenarioID: "API-BAS-ABUSE-010", Description: "POST /broker/topics/orders.retries/publish accepts publishes without any per-publisher limit.", Oracle: "more accepted publishes from one publisher than the declared limit"},
	}
}

func (s *Server) brokerPublish(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	topic := r.PathValue("topic")
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body could not be read"})
		return
	}
	var ev struct {
		Event   string `json:"event"`
		OrderID string `json:"order_id"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil || strings.TrimSpace(ev.Event) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "event must be a JSON object with an event name"})
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	switch topic {
	case "orders.events":
		if !s.vulnerable() && !validEventSignature(r.Header.Get("X-Event-Signature"), raw) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "event signature does not match the payload"})
			return
		}
		if o, found := s.orders[ev.OrderID]; found {
			switch ev.Event {
			case "order.created":
				o.Status = "created"
			case "order.cancelled":
				o.Status = "cancelled"
			}
		}
	case "orders.retries":
		if !s.vulnerable() {
			if s.brokerCounts == nil {
				s.brokerCounts = map[string]int{}
			}
			key := caller + "|" + topic
			if s.brokerCounts[key] >= brokerQuota {
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "publish limit reached for this topic"})
				return
			}
			s.brokerCounts[key]++
		}
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown topic"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "topic": topic})
}

// validEventSignature reports whether a signature header matches the body under the lab key.
func validEventSignature(header string, body []byte) bool {
	mac := hmac.New(sha256.New, []byte(brokerSigningKey))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(header), []byte(want))
}
