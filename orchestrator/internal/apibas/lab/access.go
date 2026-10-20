package lab

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
)

// accessEvent is one request as the lab observed it. It carries the run tag, the
// outcome and the owner of the order the request touched, never the token. Detection
// fixtures normalise these events themselves.
type accessEvent struct {
	Seq           int    `json:"seq"`
	CorrelationID string `json:"correlation_id"`
	Action        string `json:"action"`
	Outcome       string `json:"outcome"`
	Identity      string `json:"identity"`
	Status        int    `json:"status"`
	// ObjectOwner is the first owner the request named. It is kept for consumers that read one owner;
	// ObjectOwners carries every distinct owner named by the path, the query and (with extraction on)
	// the body, in that order. ObjectOwner is always ObjectOwners[0] when the latter is set.
	ObjectOwner  string   `json:"object_owner,omitempty"`
	ObjectOwners []string `json:"object_owners,omitempty"`
	// At is when the lab recorded the event. It is not part of the event contract: telemetry faults use
	// it to decide when the SIEM is allowed to receive the event.
	At time.Time `json:"-"`
	// Signature holds the injection-pattern classes of the request target and, when body extraction is on,
	// of the body. Classes only; no text is kept.
	Signature []string `json:"signature,omitempty"`
}

// statusRecorder keeps the status the handler wrote.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

// Hijack passes an upgrade through to the connection. A WebSocket handshake needs it, and the
// access log records the 101 it switches to.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer cannot hijack the connection")
	}
	r.status = http.StatusSwitchingProtocols
	return hj.Hijack()
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.ResponseWriter.Write(b)
}

func outcomeFor(status int) string {
	switch {
	case status == http.StatusTooManyRequests:
		return "throttled"
	case status >= 500:
		return "error"
	case status >= 400:
		return "failure"
	}
	return "success"
}

// ownersOfPath returns the owners of every order a request path names, in path order, without repeats.
// The owners come from the lab's own order records, never from the request text.
func (s *Server) ownersOfPath(path string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, seg := range strings.Split(path, "/") {
		if o, ok := s.orders[seg]; ok {
			out = appendOwner(out, o.OwnerID)
		}
	}
	return out
}

// ownersOfRequest attributes every object a request names: first from its path, then from its decoded
// query values, in order-ID order. Each owner appears once.
func (s *Server) ownersOfRequest(r *http.Request) []string {
	out := s.ownersOfPath(r.URL.Path)
	q := r.URL.Query()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, o := range sortedOrders(s.orders) {
		for _, vals := range q {
			for _, v := range vals {
				if strings.Contains(v, o.ID) {
					out = appendOwner(out, o.OwnerID)
				}
			}
		}
	}
	return out
}

// maxObjectOwners bounds the owners one event carries. The fixture has few owners, so the bound is a
// defensive cap on the event's size, not a limit a real run reaches.
const maxObjectOwners = 16

// appendOwner adds an owner once, keeping the order of first appearance and the cap.
func appendOwner(list []string, owner string) []string {
	if owner == "" || len(list) >= maxObjectOwners {
		return list
	}
	for _, o := range list {
		if o == owner {
			return list
		}
	}
	return append(list, owner)
}

// logAccess records one event per product request. Lab administration routes are not
// recorded, so the detection fixture only sees traffic the scenario sent.
func (s *Server) logAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if strings.HasPrefix(r.URL.Path, "/lab/") {
			return
		}
		identity := "anonymous"
		if caller, st := s.identify(r); st == authOK {
			identity = caller
		} else if st != authMissing {
			identity = "unknown"
		}
		owners := s.ownersOfRequest(r)
		for _, o := range bodyOwnersFromContext(r.Context()) {
			owners = appendOwner(owners, o)
		}
		owner := ""
		if len(owners) > 0 {
			owner = owners[0]
		}
		s.evMu.Lock()
		s.eventSeq++
		s.events = append(s.events, accessEvent{
			Seq:           s.eventSeq,
			CorrelationID: r.Header.Get("X-BAS-Run"),
			Action:        r.Method + " " + r.URL.Path,
			Outcome:       outcomeFor(rec.status),
			Identity:      identity,
			Status:        rec.status,
			ObjectOwner:   owner,
			ObjectOwners:  owners,
			At:            time.Now(),
			Signature:     append(injectionClasses(requestTargetText(r.URL.Path, r.URL.Query())), bodySignatureFromContext(r.Context())...),
		})
		s.evMu.Unlock()
	})
}

// getAccessEvents returns the events recorded under one run tag. An empty tag returns
// nothing, so the endpoint never dumps every run.
func (s *Server) getAccessEvents(w http.ResponseWriter, r *http.Request) {
	corr := r.URL.Query().Get("correlation_id")
	s.evMu.Lock()
	defer s.evMu.Unlock()
	out := []accessEvent{}
	if s.faultOn("telemetry-missing") {
		writeJSON(w, http.StatusOK, out)
		return
	}
	for _, e := range s.events {
		if corr != "" && e.CorrelationID == corr && s.delivered(e) {
			out = append(out, e)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// telemetryDelayed is how long the lab holds each access event back from the SIEM when the
// telemetry-delayed fault is active.
const telemetryDelayed = 3 * time.Second

// delivered reports whether an access event has reached the SIEM by now. Without the telemetry-delayed
// fault every event is delivered at once. With it, an event is delivered only once it is telemetryDelayed
// old, so a SIEM that reads inside a shorter window does not see it.
func (s *Server) delivered(e accessEvent) bool {
	if !s.faultOn("telemetry-delayed") {
		return true
	}
	return time.Since(e.At) >= telemetryDelayed
}
