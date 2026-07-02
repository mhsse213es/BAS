package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// Attack-path collection. The agent is a PURE COLLECTOR: it emits observed
// relationship/reachability facts and uploads raw SharpHound output. It never
// builds a graph or computes anything — all analytics live on the server. This
// is recon/relationship mapping only: TCP connect probes against an explicit
// server-provided host allowlist (never range scanning / discovery), local
// identity facts, and SharpHound where domain-joined. No exploitation, no
// propagation.

// AttackPathCollectCommand is the WS command payload (type
// "command_attackpath_collect"). Targets is an explicit allowlist — the agent
// probes only these hosts. SharpHoundPayload, when present and the host is
// domain-joined, is written to a temp dir and executed; its raw output zip is
// uploaded for server-side parsing.
type AttackPathCollectCommand struct {
	CollectID         string   `json:"collectId"`
	JobID             string   `json:"jobId,omitempty"` // server-assigned job ID for ACK + progress
	Targets           []string `json:"targets"`
	Segment           string   `json:"segment,omitempty"`
	RunSharpHound     bool     `json:"runSharpHound,omitempty"`
	SharpHoundPayload *Payload `json:"sharpHoundPayload,omitempty"`
	SharpHoundArgs    string   `json:"sharpHoundArgs,omitempty"`
}

// Wire types mirroring the server's attackpath.Collection (separate module).
type apNode struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Label      string `json:"label,omitempty"`
	Role       string `json:"role,omitempty"`
	Segment    string `json:"segment,omitempty"`
	CrownJewel string `json:"crownJewel,omitempty"`
	HighValue  bool   `json:"highValue,omitempty"`
}

type apEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

type apCollection struct {
	AgentID     string    `json:"agentId"`
	Hostname    string    `json:"hostname"`
	Source      string    `json:"source"`
	CollectedAt time.Time `json:"collectedAt"`
	Nodes       []apNode  `json:"nodes"`
	Edges       []apEdge  `json:"edges"`
	JobID       string    `json:"jobId,omitempty"` // echoed from command for server-side job completion
}

// reachProbes maps an edge kind to the TCP port that signals reachability.
var reachProbes = []struct {
	kind string
	port string
}{
	{"smb", "445"},
	{"winrm", "5985"},
	{"rdp", "3389"},
}

const probeTimeout = 1500 * time.Millisecond

// runAttackPathCollect executes one collection and submits it. Errors are logged,
// never fatal — a failed probe or a missing SharpHound just yields a smaller
// graph.
func (a *Agent) runAttackPathCollect(cmd AttackPathCollectCommand) {
	// ACK immediately so the server knows we received the job and can transition
	// dispatched→running. Fire-and-forget — a failed ACK doesn't abort the work.
	if cmd.JobID != "" {
		if err := a.postJSON("/api/attackpath/jobs/"+cmd.JobID+"/ack", map[string]string{"agentId": a.id.AgentID}); err != nil {
			log.Printf("[attackpath] ACK failed (job=%s): %v", cmd.JobID, err)
		}
		// Expose the job in heartbeats so the server can track that we're alive.
		a.setCurrentJob(cmd.JobID, "probing", 0, len(cmd.Targets))
		defer a.clearCurrentJob()
	}

	self := strings.ToUpper(shortHostname(a.id.Hostname))
	role := "endpoint"
	if hostIsDomainController() {
		role = "domain-controller"
	}
	col := apCollection{
		AgentID:     a.id.AgentID,
		Hostname:    a.id.Hostname,
		Source:      "agent",
		CollectedAt: time.Now().UTC(),
		JobID:       cmd.JobID,
	}
	col.Nodes = append(col.Nodes, apNode{ID: self, Kind: "host", Label: a.id.Hostname, Role: role, Segment: cmd.Segment})

	// Local-admin principals → admin-to self.
	for _, p := range collectLocalAdmins() {
		id := strings.ToUpper(p)
		col.Nodes = append(col.Nodes, apNode{ID: id, Kind: "user", Label: p})
		col.Edges = append(col.Edges, apEdge{From: id, To: self, Kind: "admin-to"})
	}

	// Interactive sessions → self has-session user (creds harvestable here).
	for _, u := range collectSessions(a.id.Username) {
		id := strings.ToUpper(u)
		col.Nodes = append(col.Nodes, apNode{ID: id, Kind: "user", Label: u})
		col.Edges = append(col.Edges, apEdge{From: self, To: id, Kind: "has-session"})
	}

	// Reachability probes against the explicit allowlist only.
	total := len(cmd.Targets)
	for i, t := range cmd.Targets {
		t = strings.TrimSpace(t)
		if t == "" || strings.EqualFold(shortHostname(t), shortHostname(a.id.Hostname)) {
			continue
		}
		tid := strings.ToUpper(shortHostname(t))
		reached := false
		for _, p := range reachProbes {
			if tcpReachable(t, p.port) {
				col.Edges = append(col.Edges, apEdge{From: self, To: tid, Kind: p.kind})
				reached = true
			}
		}
		if reached {
			col.Nodes = append(col.Nodes, apNode{ID: tid, Kind: "host", Label: t})
		}
		// Update progress every 5 targets so heartbeats carry fresh counts.
		if cmd.JobID != "" && (i+1)%5 == 0 {
			a.setCurrentJob(cmd.JobID, "probing", i+1, total)
		}
	}

	if cmd.JobID != "" {
		a.setCurrentJob(cmd.JobID, "uploading", total, total)
	}

	if err := a.postJSON("/api/attackpath/collect", col); err != nil {
		log.Printf("[attackpath] collect submit failed: %v", err)
	} else {
		log.Printf("[attackpath] collected %d nodes, %d edges (collectId=%s job=%s)",
			len(col.Nodes), len(col.Edges), cmd.CollectID, cmd.JobID)
	}

	// SharpHound (domain-joined only). The agent uploads the RAW zip; the server
	// parses it. Gated by the server flag + domain membership.
	if cmd.RunSharpHound && cmd.SharpHoundPayload != nil && hostIsDomainJoined() {
		a.runAndUploadSharpHound(cmd)
	}
}

// runAndUploadSharpHound writes the provided SharpHound binary to a temp dir,
// runs it, finds the output zip, and uploads the raw bytes.
func (a *Agent) runAndUploadSharpHound(cmd AttackPathCollectCommand) {
	zipBytes, err := runSharpHound(cmd.SharpHoundPayload, cmd.SharpHoundArgs)
	if err != nil {
		log.Printf("[attackpath] SharpHound run failed: %v", err)
		return
	}
	if len(zipBytes) == 0 {
		log.Printf("[attackpath] SharpHound produced no output")
		return
	}
	if err := a.postRaw("/api/attackpath/sharphound?agentId="+a.id.AgentID+"&hostname="+a.id.Hostname,
		"application/zip", zipBytes); err != nil {
		log.Printf("[attackpath] SharpHound upload failed: %v", err)
		return
	}
	log.Printf("[attackpath] SharpHound output uploaded (%d bytes)", len(zipBytes))
}

// postRaw POSTs raw bytes with the agent token (mirrors postJSONDecode auth).
func (a *Agent) postRaw(path, contentType string, body []byte) error {
	req, err := http.NewRequest(http.MethodPost, a.cfg.ServerURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	if a.cfg.AgentSecret != "" {
		req.Header.Set("X-Agent-Token", a.cfg.AgentSecret)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server %d on %s", resp.StatusCode, path)
	}
	return nil
}

// tcpReachable reports whether host:port accepts a TCP connection.
func tcpReachable(host, port string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), probeTimeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// shortHostname strips a DNS suffix: "DC01.corp.local" → "DC01". IP literals are
// left whole so an address is never truncated to its first octet (which would
// make every host in a /8 share one node ID).
func shortHostname(h string) string {
	if net.ParseIP(h) != nil {
		return h
	}
	if i := strings.IndexByte(h, '.'); i > 0 {
		return h[:i]
	}
	return h
}
