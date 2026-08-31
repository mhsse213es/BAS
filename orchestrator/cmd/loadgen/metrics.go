package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics aggregates client-side observations across every simulated agent
// in one loadgen run. All fields are safe for concurrent use.
type Metrics struct {
	activeAgents int64 // atomic gauge

	mu                    sync.Mutex
	enrollLatencies       []time.Duration
	wsConnectLatencies    []time.Duration
	heartbeatOK           int64
	heartbeatFailed       int64
	dispatchLatencies     []time.Duration
	resultSubmitLatencies []time.Duration
	reconnectLatencies    []time.Duration
	connectionDrops       int64
	protocolErrors        int64
	httpErrors            int64
	messagesTotal         int64
	resultsTotal          int64
}

func NewMetrics() *Metrics { return &Metrics{} }

func (m *Metrics) AgentStarted()       { atomic.AddInt64(&m.activeAgents, 1) }
func (m *Metrics) AgentStopped()       { atomic.AddInt64(&m.activeAgents, -1) }
func (m *Metrics) ActiveAgents() int64 { return atomic.LoadInt64(&m.activeAgents) }

func (m *Metrics) RecordEnroll(d time.Duration) {
	m.mu.Lock()
	m.enrollLatencies = append(m.enrollLatencies, d)
	m.mu.Unlock()
}
func (m *Metrics) RecordWSConnect(d time.Duration) {
	m.mu.Lock()
	m.wsConnectLatencies = append(m.wsConnectLatencies, d)
	m.mu.Unlock()
}
func (m *Metrics) RecordHeartbeat(ok bool) {
	if ok {
		atomic.AddInt64(&m.heartbeatOK, 1)
	} else {
		atomic.AddInt64(&m.heartbeatFailed, 1)
	}
}
func (m *Metrics) RecordDispatch(d time.Duration) {
	m.mu.Lock()
	m.dispatchLatencies = append(m.dispatchLatencies, d)
	m.mu.Unlock()
	atomic.AddInt64(&m.messagesTotal, 1)
}
func (m *Metrics) RecordResultSubmit(d time.Duration) {
	m.mu.Lock()
	m.resultSubmitLatencies = append(m.resultSubmitLatencies, d)
	m.mu.Unlock()
	atomic.AddInt64(&m.resultsTotal, 1)
}
func (m *Metrics) RecordReconnect(d time.Duration) {
	m.mu.Lock()
	m.reconnectLatencies = append(m.reconnectLatencies, d)
	m.mu.Unlock()
}
func (m *Metrics) RecordConnectionDrop() { atomic.AddInt64(&m.connectionDrops, 1) }
func (m *Metrics) RecordProtocolError()  { atomic.AddInt64(&m.protocolErrors, 1) }
func (m *Metrics) RecordHTTPError()      { atomic.AddInt64(&m.httpErrors, 1) }

// Snapshot is a point-in-time, human-readable summary.
type Snapshot struct {
	ActiveAgents    int64
	HeartbeatOK     int64
	HeartbeatFailed int64
	ConnectionDrops int64
	ProtocolErrors  int64
	HTTPErrors      int64
	MessagesTotal   int64
	ResultsTotal    int64

	EnrollP50, EnrollP95       time.Duration
	WSConnectP50, WSConnectP95 time.Duration
	DispatchP50, DispatchP95   time.Duration
	ResultP50, ResultP95       time.Duration
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func (m *Metrics) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	enroll := sortedCopy(m.enrollLatencies)
	ws := sortedCopy(m.wsConnectLatencies)
	dispatch := sortedCopy(m.dispatchLatencies)
	result := sortedCopy(m.resultSubmitLatencies)
	return Snapshot{
		ActiveAgents:    atomic.LoadInt64(&m.activeAgents),
		HeartbeatOK:     m.heartbeatOK,
		HeartbeatFailed: m.heartbeatFailed,
		ConnectionDrops: m.connectionDrops,
		ProtocolErrors:  m.protocolErrors,
		HTTPErrors:      m.httpErrors,
		MessagesTotal:   m.messagesTotal,
		ResultsTotal:    m.resultsTotal,
		EnrollP50:       percentile(enroll, 0.50),
		EnrollP95:       percentile(enroll, 0.95),
		WSConnectP50:    percentile(ws, 0.50),
		WSConnectP95:    percentile(ws, 0.95),
		DispatchP50:     percentile(dispatch, 0.50),
		DispatchP95:     percentile(dispatch, 0.95),
		ResultP50:       percentile(result, 0.50),
		ResultP95:       percentile(result, 0.95),
	}
}

func sortedCopy(in []time.Duration) []time.Duration {
	out := make([]time.Duration, len(in))
	copy(out, in)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

func (s Snapshot) String() string {
	return fmt.Sprintf(
		"active=%d hb_ok=%d hb_fail=%d drops=%d proto_err=%d http_err=%d msgs=%d results=%d "+
			"enroll_p50=%s enroll_p95=%s ws_p50=%s ws_p95=%s dispatch_p50=%s dispatch_p95=%s result_p50=%s result_p95=%s",
		s.ActiveAgents, s.HeartbeatOK, s.HeartbeatFailed, s.ConnectionDrops, s.ProtocolErrors, s.HTTPErrors, s.MessagesTotal, s.ResultsTotal,
		s.EnrollP50, s.EnrollP95, s.WSConnectP50, s.WSConnectP95, s.DispatchP50, s.DispatchP95, s.ResultP50, s.ResultP95,
	)
}
