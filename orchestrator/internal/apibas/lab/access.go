package lab

import (
	"net/http"
	"strings"
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
	ObjectOwner   string `json:"object_owner,omitempty"`
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

// ownerOfPath returns the owner of the order a /api/orders/{id}... path names, or ""
// when the path names no order.
func (s *Server) ownerOfPath(path string) string {
	const prefix = "/api/orders/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	id := strings.SplitN(strings.TrimPrefix(path, prefix), "/", 2)[0]
	s.mu.Lock()
	defer s.mu.Unlock()
	if o, ok := s.orders[id]; ok {
		return o.OwnerID
	}
	return ""
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
		owner := s.ownerOfPath(r.URL.Path)
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
	for _, e := range s.events {
		if corr != "" && e.CorrelationID == corr {
			out = append(out, e)
		}
	}
	writeJSON(w, http.StatusOK, out)
}
