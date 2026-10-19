package ws

// RegisterTestAgent connects a stand-in agent with no socket, so dispatch can
// reach SendToAgent in tests. Each message sent to the agent is queued on the
// returned channel as the JSON the agent would receive. Production code never
// calls this.
func (h *Hub) RegisterTestAgent(agentID string) <-chan []byte {
	c := &conn{send: make(chan []byte, 16), done: make(chan struct{})}
	h.mu.Lock()
	h.agents[agentID] = c
	h.mu.Unlock()
	return c.send
}
