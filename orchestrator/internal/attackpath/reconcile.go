package attackpath

import "strings"

// reconcileHosts collapses host nodes that refer to the same physical machine but
// were reported under different identities by different collectors. Reachability
// collection keys hosts by short hostname (e.g. "DC01"); SharpHound keys them by
// SID (e.g. "S-1-5-21-…-1001") with the FQDN in the label ("DC01.CORP.LOCAL").
// Left unmerged the two are separate nodes — the reachability subgraph and the
// AD-identity subgraph never connect, and host counts double.
//
// We pick the SID as canonical (it anchors the admin-to / has-session / member-of
// edges) and rewrite the hostname node's reachability edges onto it. The result:
// a reachability entry host can traverse straight into the AD graph — e.g. an
// endpoint that reaches a file server over SMB inherits that server's session →
// user → Domain Admin path. Only hosts are reconciled; users/groups stay
// SID-keyed (hostname-style name collisions there are unsafe to merge).
func (g *Graph) reconcileHosts() {
	// canonical[hostKey] = chosen node ID for that machine.
	canonical := map[string]string{}
	for _, n := range g.nodes {
		if n.Kind != KindHost {
			continue
		}
		key := hostKey(n)
		if key == "" {
			continue
		}
		cur, ok := canonical[key]
		if !ok {
			canonical[key] = n.ID
			continue
		}
		// Prefer a SID-keyed node as canonical so AD edges need no rewrite.
		if isSID(n.ID) && !isSID(cur) {
			canonical[key] = n.ID
		}
	}

	remap := map[string]string{}
	for _, n := range g.nodes {
		if n.Kind != KindHost {
			continue
		}
		key := hostKey(n)
		if c := canonical[key]; key != "" && c != "" && c != n.ID {
			remap[n.ID] = c
		}
	}
	if len(remap) == 0 {
		return
	}

	// Merge each remapped node's metadata into its canonical, then drop it.
	for old, c := range remap {
		o := g.nodes[old]
		cn := g.nodes[c]
		enrichHost(&cn, o)
		g.nodes[c] = cn
		delete(g.nodes, old)
	}

	// Rewrite every edge through the remap, dropping self-loops and duplicates.
	newAdj := map[string][]Edge{}
	seen := map[Edge]bool{}
	for _, es := range g.adj {
		for _, e := range es {
			e.From = resolve(e.From, remap)
			e.To = resolve(e.To, remap)
			if e.From == e.To || seen[e] {
				continue
			}
			seen[e] = true
			newAdj[e.From] = append(newAdj[e.From], e)
		}
	}
	g.adj = newAdj
}

// hostKey is the machine's reconciliation key: its short hostname, uppercased.
// SID-keyed nodes derive it from the FQDN label; hostname-keyed nodes from the ID.
func hostKey(n Node) string {
	src := n.ID
	if isSID(n.ID) {
		src = n.Label // SharpHound: ID is a SID, label is the FQDN
	}
	return strings.ToUpper(shortHost(src))
}

// enrichHost fills empty fields on the canonical host from a node being merged
// into it (e.g. the reachability node usually carries the network Segment; the
// SharpHound node carries the AD Role). Never blanks an existing value.
func enrichHost(dst *Node, src Node) {
	if dst.Label == "" {
		dst.Label = src.Label
	}
	if dst.Role == "" || dst.Role == RoleEndpoint {
		// A specific role (server/DC) from either source beats the bare endpoint default.
		if src.Role != "" && src.Role != RoleEndpoint {
			dst.Role = src.Role
		} else if dst.Role == "" {
			dst.Role = src.Role
		}
	}
	if dst.Segment == "" {
		dst.Segment = src.Segment
	}
	if dst.CrownJewel == "" {
		dst.CrownJewel = src.CrownJewel
	}
	if src.HighValue {
		dst.HighValue = true
	}
}

func resolve(id string, remap map[string]string) string {
	if to, ok := remap[id]; ok {
		return to
	}
	return id
}

func isSID(id string) bool { return strings.HasPrefix(strings.ToUpper(id), "S-1-") }

// shortHost strips a DNS suffix: "DC01.corp.local" → "DC01".
func shortHost(h string) string {
	if i := strings.IndexByte(h, '.'); i > 0 {
		return h[:i]
	}
	return h
}
