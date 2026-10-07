// Package attackpath is the native attack-path engine: it turns the relationship
// and reachability edges collected by agents (SMB/WinRM/RDP reachability, local
// admin, AD sessions/memberships, SharpHound) into a graph and answers the
// questions ART and Caldera cannot — "if this host is compromised, how far can
// an attacker go, and can they reach Domain Admin or a crown jewel?".
//
// It is recon/relationship analysis only: no exploitation, no propagation. All
// logic lives here on the server (the agent only collects edges).
package attackpath

// NodeKind is the category of a graph node.
type NodeKind string

const (
	KindHost  NodeKind = "host"
	KindUser  NodeKind = "user"
	KindGroup NodeKind = "group"
)

// HostRole classifies a host for reachability reporting.
type HostRole string

const (
	RoleEndpoint HostRole = "endpoint"
	RoleServer   HostRole = "server"
	RoleDC       HostRole = "domain-controller"
)

// Node is a vertex: a host, a user, or a group.
type Node struct {
	ID         string   `json:"id"`                   // stable identity (hostname, SID, user@domain)
	Kind       NodeKind `json:"kind"`                 // host | user | group
	Label      string   `json:"label"`                // human-readable name
	Role       HostRole `json:"role,omitempty"`       // hosts only
	Segment    string   `json:"segment,omitempty"`    // network segment / VLAN tag (for segmentation analysis)
	CrownJewel string   `json:"crownJewel,omitempty"` // "" or a tag like "ERP", "FileServer", "Backup"
	HighValue  bool     `json:"highValue,omitempty"`  // Domain Admins group / DA-equivalent (domain-compromise target)

	// SP6 asset criticality — operator-tagged, same overlay mechanism as
	// CrownJewel/HighValue above. Role==RoleDC (already set from SharpHound
	// data, see sharphound.go) is the one criticality signal NOT tagged here.
	CriticalityTier string   `json:"criticalityTier,omitempty"` // "" | low | medium | high | critical
	InternetFacing  bool     `json:"internetFacing,omitempty"`
	IdentityExposed bool     `json:"identityExposed,omitempty"`
	Production      bool     `json:"production,omitempty"`
	ComplianceScope []string `json:"complianceScope,omitempty"`

	// UnconstrainedDelegation marks a principal (computer or user) configured
	// for unconstrained Kerberos delegation: whoever controls it can harvest
	// and reuse the TGT of ANY user who authenticates to it. Deliberately a
	// flag, not an edge -- there is no single fixed target to draw an edge
	// to. See docs/superpowers/specs/2026-10-07-ad-acl-delegation-graph-model-design.md.
	UnconstrainedDelegation bool `json:"unconstrainedDelegation,omitempty"`
}

// EdgeKind is a traversable relationship an attacker can use.
type EdgeKind string

const (
	EdgeSMB        EdgeKind = "smb"         // From can reach To over SMB (445)
	EdgeWinRM      EdgeKind = "winrm"       // From can reach To over WinRM (5985/5986)
	EdgeRDP        EdgeKind = "rdp"         // From can reach To over RDP (3389)
	EdgeAdminTo    EdgeKind = "admin-to"    // user/group is local admin on host
	EdgeHasSession EdgeKind = "has-session" // host has an interactive session for user (creds harvestable)
	EdgeMemberOf   EdgeKind = "member-of"   // user/group is a member of group
	EdgeCredential EdgeKind = "credential"  // reusable credential edge (e.g. shared local-admin password)

	// ACL-abuse edges (from SharpHound's Aces arrays). From = the ACE's
	// PrincipalSID (the grantee, who an attacker must control); To = the
	// object the Aces array is attached to (whose rights the grantee holds).
	// See docs/superpowers/specs/2026-10-07-ad-acl-delegation-graph-model-design.md.
	EdgeGenericAll           EdgeKind = "generic-all"
	EdgeGenericWrite         EdgeKind = "generic-write"
	EdgeWriteOwner           EdgeKind = "write-owner"
	EdgeWriteDacl            EdgeKind = "write-dacl"
	EdgeOwns                 EdgeKind = "owns"
	EdgeAllExtendedRights    EdgeKind = "all-extended-rights"
	EdgeForceChangePassword  EdgeKind = "force-change-password"
	EdgeAddMember            EdgeKind = "add-member"
	EdgeAddSelf              EdgeKind = "add-self"
	EdgeAddKeyCredentialLink EdgeKind = "add-key-credential-link"
	EdgeReadLAPSPassword     EdgeKind = "read-laps-password"

	// Kerberos delegation-abuse edges. See the spec's direction table --
	// AllowedToDelegate and AllowedToAct have OPPOSITE grantee positions
	// relative to "the computer carrying the JSON property".
	EdgeAllowedToDelegate EdgeKind = "allowed-to-delegate"
	EdgeAllowedToAct      EdgeKind = "allowed-to-act"
)

// reachKinds are the edge kinds that represent host-to-host lateral movement
// (used for blast radius, segmentation, and reachability host counts).
var reachKinds = map[EdgeKind]bool{EdgeSMB: true, EdgeWinRM: true, EdgeRDP: true}

// Edge is a directed relationship From → To.
type Edge struct {
	From string   `json:"from"`
	To   string   `json:"to"`
	Kind EdgeKind `json:"kind"`
}

// Graph is a directed multigraph of nodes and traversable edges.
type Graph struct {
	nodes map[string]Node
	adj   map[string][]Edge
}

// New returns an empty graph.
func New() *Graph {
	return &Graph{nodes: map[string]Node{}, adj: map[string][]Edge{}}
}

// AddNode inserts or replaces a node by ID.
func (g *Graph) AddNode(n Node) {
	if n.ID == "" {
		return
	}
	g.nodes[n.ID] = n
}

// AddEdge records a directed edge. Endpoints that have no explicit node are
// created as bare host nodes so collection order never drops an edge.
func (g *Graph) AddEdge(e Edge) {
	if e.From == "" || e.To == "" {
		return
	}
	for _, id := range []string{e.From, e.To} {
		if _, ok := g.nodes[id]; !ok {
			g.nodes[id] = Node{ID: id, Kind: KindHost, Label: id, Role: RoleEndpoint}
		}
	}
	g.adj[e.From] = append(g.adj[e.From], e)
}

// Node returns a node by ID.
func (g *Graph) Node(id string) (Node, bool) { n, ok := g.nodes[id]; return n, ok }

// Nodes returns all nodes (order unspecified).
func (g *Graph) Nodes() []Node {
	out := make([]Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		out = append(out, n)
	}
	return out
}

// NodeCount / EdgeCount are sizes.
func (g *Graph) NodeCount() int { return len(g.nodes) }
func (g *Graph) EdgeCount() int {
	n := 0
	for _, es := range g.adj {
		n += len(es)
	}
	return n
}

// Edges returns every edge in the graph (order unspecified). Used by
// internal/recommend to decide which ATT&CK techniques are relevant to this
// environment — adj is unexported, so there is no other way to enumerate them.
func (g *Graph) Edges() []Edge {
	out := make([]Edge, 0, g.EdgeCount())
	for _, es := range g.adj {
		out = append(out, es...)
	}
	return out
}

// EdgesTo returns every edge whose To == id (order unspecified). Used by
// internal/pathcorrelation to find the edges that make a choke-point node
// dangerous.
func (g *Graph) EdgesTo(id string) []Edge {
	var out []Edge
	for _, es := range g.adj {
		for _, e := range es {
			if e.To == id {
				out = append(out, e)
			}
		}
	}
	return out
}
