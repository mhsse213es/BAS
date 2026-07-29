package threatgraph

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/intelligence"
	"github.com/audspect/bas/internal/reporting/attackdata"
)

// techniqueLabel looks up a technique's display name, falling back to the
// ID itself if not found (a technique referenced by intelligence data
// should always exist in the techniques table, but this is a display
// concern, not a hard failure).
func techniqueLabel(ctx context.Context, pool *pgxpool.Pool, id string) (string, error) {
	var name string
	err := pool.QueryRow(ctx, `SELECT name FROM techniques WHERE technique_id = $1`, id).Scan(&name)
	if err == pgx.ErrNoRows {
		return id, nil
	}
	if err != nil {
		return "", err
	}
	if name == "" {
		return id, nil
	}
	return name, nil
}

// addTechniques appends one technique node and one "uses" edge (from ->
// technique) per ID in techIDs. Shared by every neighborhood function that
// has a TechniqueIDs list (actor via GroupTechniqueIndex, campaign,
// malware, tool).
func addTechniques(ctx context.Context, pool *pgxpool.Pool, n *Neighborhood, from string, techIDs []string) error {
	for _, id := range techIDs {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id == "" {
			continue
		}
		label, err := techniqueLabel(ctx, pool, id)
		if err != nil {
			return err
		}
		nodeID := "technique:" + id
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeTechnique, Label: label})
		n.Edges = append(n.Edges, Edge{From: from, To: nodeID, Relationship: "uses"})
	}
	return nil
}

// addActors appends one actor node and one edge (actor -> from) per name.
// No DB lookup needed: an actor's label is its own name, already known to
// the caller (unlike campaign/malware/tool, which need a lookup to get a
// display name from an ID).
func addActors(n *Neighborhood, from string, names []string, relationship string) {
	for _, name := range names {
		if name == "" {
			continue
		}
		nodeID := "actor:" + intelligence.NormalizeKey(name)
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeActor, Label: name})
		n.Edges = append(n.Edges, Edge{From: nodeID, To: from, Relationship: relationship})
	}
}

// addCampaigns appends one campaign node and one edge (campaign -> from)
// per ID in ids, in a single batched query. Shared by Malware/Tool
// neighborhoods (their own CampaignIDs) via "used_in".
func addCampaigns(ctx context.Context, pool *pgxpool.Pool, n *Neighborhood, from string, ids []string, relationship string) error {
	if len(ids) == 0 {
		return nil
	}
	rows, err := pool.Query(ctx, `SELECT id, name FROM intelligence_campaigns WHERE id = ANY($1)`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return err
		}
		nodeID := "campaign:" + id
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeCampaign, Label: name})
		n.Edges = append(n.Edges, Edge{From: nodeID, To: from, Relationship: relationship})
	}
	return rows.Err()
}

// TechniqueNeighborhood assembles the 1-hop neighborhood around a
// technique: every actor whose GroupTechniqueIndex() entry contains it
// (linear scan -- the index is small and cached, see the design doc's
// Non-Goals on why a reverse index isn't built), plus every
// campaign/malware/tool whose TechniqueIDs contains it.
func TechniqueNeighborhood(ctx context.Context, pool *pgxpool.Pool, techniqueID string) (Neighborhood, error) {
	techniqueID = strings.ToUpper(strings.TrimSpace(techniqueID))
	n := Neighborhood{Nodes: []Node{}, Edges: []Edge{}}
	techNodeID := "technique:" + techniqueID

	var relatedNodes []Node
	var relatedEdges []Edge

	for actorName, techIDs := range attackdata.GroupTechniqueIndex() {
		for _, t := range techIDs {
			if strings.ToUpper(t) == techniqueID {
				actorNodeID := "actor:" + intelligence.NormalizeKey(actorName)
				relatedNodes = append(relatedNodes, Node{ID: actorNodeID, Type: NodeTypeActor, Label: actorName})
				relatedEdges = append(relatedEdges, Edge{From: actorNodeID, To: techNodeID, Relationship: "uses"})
				break
			}
		}
	}

	for _, table := range []struct {
		name     string
		nodeType string
	}{
		{"intelligence_campaigns", NodeTypeCampaign},
		{"intelligence_malware", NodeTypeMalware},
		{"intelligence_tools", NodeTypeTool},
	} {
		var rows pgx.Rows
		var err error
		switch table.name {
		case "intelligence_campaigns":
			rows, err = pool.Query(ctx, `SELECT id, name FROM intelligence_campaigns WHERE $1 = ANY(technique_ids)`, techniqueID)
		case "intelligence_malware":
			rows, err = pool.Query(ctx, `SELECT id, name FROM intelligence_malware WHERE $1 = ANY(technique_ids)`, techniqueID)
		case "intelligence_tools":
			rows, err = pool.Query(ctx, `SELECT id, name FROM intelligence_tools WHERE $1 = ANY(technique_ids)`, techniqueID)
		}
		if err != nil {
			return n, err
		}
		for rows.Next() {
			var id, name string
			if err := rows.Scan(&id, &name); err != nil {
				rows.Close()
				return n, err
			}
			nodeID := table.nodeType + ":" + id
			relatedNodes = append(relatedNodes, Node{ID: nodeID, Type: table.nodeType, Label: name})
			relatedEdges = append(relatedEdges, Edge{From: nodeID, To: techNodeID, Relationship: "uses"})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return n, err
		}
	}

	// A technique with zero real relationships (not in GroupTechniqueIndex,
	// not referenced by any campaign/malware/tool) doesn't exist as far as
	// this graph is concerned -- existence is driven by having a
	// relationship, not by a row in the techniques catalog table (which may
	// not be seeded yet in every deployment/test environment).
	if len(relatedNodes) == 0 {
		return n, nil
	}

	label, err := techniqueLabel(ctx, pool, techniqueID)
	if err != nil {
		return n, err
	}
	n.Nodes = append(n.Nodes, Node{ID: techNodeID, Type: NodeTypeTechnique, Label: label})
	n.Nodes = append(n.Nodes, relatedNodes...)
	n.Edges = append(n.Edges, relatedEdges...)

	return n, nil
}

// ActorNeighborhood assembles the 1-hop neighborhood around a threat
// actor: its techniques (attackdata.GroupTechniqueIndex(), keyed by
// canonical actor name), campaigns/malware/tools that list it in their
// ThreatActorIDs, and its sectors/regions (threat_actor_profiles).
func ActorNeighborhood(ctx context.Context, pool *pgxpool.Pool, name string) (Neighborhood, error) {
	n := Neighborhood{Nodes: []Node{}, Edges: []Edge{}}

	var sectors, regions []string
	err := pool.QueryRow(ctx, `SELECT sectors, regions FROM threat_actor_profiles WHERE name = $1`, name).Scan(&sectors, &regions)
	if err == pgx.ErrNoRows {
		return n, nil
	}
	if err != nil {
		return n, err
	}

	actorID := "actor:" + intelligence.NormalizeKey(name)
	n.Nodes = append(n.Nodes, Node{ID: actorID, Type: NodeTypeActor, Label: name})

	if err := addTechniques(ctx, pool, &n, actorID, attackdata.GroupTechniqueIndex()[name]); err != nil {
		return n, err
	}

	campaignRows, err := pool.Query(ctx, `SELECT id, name FROM intelligence_campaigns WHERE $1 = ANY(actor_ids)`, name)
	if err != nil {
		return n, err
	}
	for campaignRows.Next() {
		var id, cname string
		if err := campaignRows.Scan(&id, &cname); err != nil {
			campaignRows.Close()
			return n, err
		}
		nodeID := "campaign:" + id
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeCampaign, Label: cname})
		n.Edges = append(n.Edges, Edge{From: actorID, To: nodeID, Relationship: "attributed_to"})
	}
	campaignRows.Close()
	if err := campaignRows.Err(); err != nil {
		return n, err
	}

	malwareRows, err := pool.Query(ctx, `SELECT id, name FROM intelligence_malware WHERE $1 = ANY(actor_ids)`, name)
	if err != nil {
		return n, err
	}
	for malwareRows.Next() {
		var id, mname string
		if err := malwareRows.Scan(&id, &mname); err != nil {
			malwareRows.Close()
			return n, err
		}
		nodeID := "malware:" + id
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeMalware, Label: mname})
		n.Edges = append(n.Edges, Edge{From: actorID, To: nodeID, Relationship: "uses"})
	}
	malwareRows.Close()
	if err := malwareRows.Err(); err != nil {
		return n, err
	}

	toolRows, err := pool.Query(ctx, `SELECT id, name FROM intelligence_tools WHERE $1 = ANY(actor_ids)`, name)
	if err != nil {
		return n, err
	}
	for toolRows.Next() {
		var id, tname string
		if err := toolRows.Scan(&id, &tname); err != nil {
			toolRows.Close()
			return n, err
		}
		nodeID := "tool:" + id
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeTool, Label: tname})
		n.Edges = append(n.Edges, Edge{From: actorID, To: nodeID, Relationship: "uses"})
	}
	toolRows.Close()
	if err := toolRows.Err(); err != nil {
		return n, err
	}

	for _, s := range sectors {
		nodeID := "sector:" + intelligence.NormalizeKey(s)
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeSector, Label: s})
		n.Edges = append(n.Edges, Edge{From: actorID, To: nodeID, Relationship: "targets"})
	}
	for _, r := range regions {
		nodeID := "region:" + intelligence.NormalizeKey(r)
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeRegion, Label: r})
		n.Edges = append(n.Edges, Edge{From: actorID, To: nodeID, Relationship: "targets"})
	}

	return n, nil
}

// CampaignNeighborhood assembles the 1-hop neighborhood around a
// campaign: its own ThreatActorIDs and TechniqueIDs, plus every
// malware/tool that references it in their CampaignIDs (the reverse
// direction -- Campaign itself stores no MalwareIDs/ToolIDs).
func CampaignNeighborhood(ctx context.Context, pool *pgxpool.Pool, id string) (Neighborhood, error) {
	n := Neighborhood{Nodes: []Node{}, Edges: []Edge{}}

	var name string
	var actorIDs, techIDs []string
	err := pool.QueryRow(ctx, `SELECT name, actor_ids, technique_ids FROM intelligence_campaigns WHERE id = $1`, id).
		Scan(&name, &actorIDs, &techIDs)
	if err == pgx.ErrNoRows {
		return n, nil
	}
	if err != nil {
		return n, err
	}

	campaignID := "campaign:" + id
	n.Nodes = append(n.Nodes, Node{ID: campaignID, Type: NodeTypeCampaign, Label: name})

	addActors(&n, campaignID, actorIDs, "attributed_to")
	if err := addTechniques(ctx, pool, &n, campaignID, techIDs); err != nil {
		return n, err
	}

	malwareRows, err := pool.Query(ctx, `SELECT id, name FROM intelligence_malware WHERE $1 = ANY(campaign_ids)`, id)
	if err != nil {
		return n, err
	}
	for malwareRows.Next() {
		var mid, mname string
		if err := malwareRows.Scan(&mid, &mname); err != nil {
			malwareRows.Close()
			return n, err
		}
		nodeID := "malware:" + mid
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeMalware, Label: mname})
		n.Edges = append(n.Edges, Edge{From: nodeID, To: campaignID, Relationship: "used_in"})
	}
	malwareRows.Close()
	if err := malwareRows.Err(); err != nil {
		return n, err
	}

	toolRows, err := pool.Query(ctx, `SELECT id, name FROM intelligence_tools WHERE $1 = ANY(campaign_ids)`, id)
	if err != nil {
		return n, err
	}
	for toolRows.Next() {
		var tid, tname string
		if err := toolRows.Scan(&tid, &tname); err != nil {
			toolRows.Close()
			return n, err
		}
		nodeID := "tool:" + tid
		n.Nodes = append(n.Nodes, Node{ID: nodeID, Type: NodeTypeTool, Label: tname})
		n.Edges = append(n.Edges, Edge{From: nodeID, To: campaignID, Relationship: "used_in"})
	}
	toolRows.Close()
	if err := toolRows.Err(); err != nil {
		return n, err
	}

	return n, nil
}

// MalwareNeighborhood assembles the 1-hop neighborhood around a malware
// family: its own ThreatActorIDs, TechniqueIDs, and CampaignIDs.
func MalwareNeighborhood(ctx context.Context, pool *pgxpool.Pool, id string) (Neighborhood, error) {
	n := Neighborhood{Nodes: []Node{}, Edges: []Edge{}}

	var name string
	var actorIDs, techIDs, campaignIDs []string
	err := pool.QueryRow(ctx, `SELECT name, actor_ids, technique_ids, campaign_ids FROM intelligence_malware WHERE id = $1`, id).
		Scan(&name, &actorIDs, &techIDs, &campaignIDs)
	if err == pgx.ErrNoRows {
		return n, nil
	}
	if err != nil {
		return n, err
	}

	malwareID := "malware:" + id
	n.Nodes = append(n.Nodes, Node{ID: malwareID, Type: NodeTypeMalware, Label: name})

	addActors(&n, malwareID, actorIDs, "uses")
	if err := addTechniques(ctx, pool, &n, malwareID, techIDs); err != nil {
		return n, err
	}
	if err := addCampaigns(ctx, pool, &n, malwareID, campaignIDs, "used_in"); err != nil {
		return n, err
	}
	return n, nil
}

// ToolNeighborhood mirrors MalwareNeighborhood exactly (same field shape).
func ToolNeighborhood(ctx context.Context, pool *pgxpool.Pool, id string) (Neighborhood, error) {
	n := Neighborhood{Nodes: []Node{}, Edges: []Edge{}}

	var name string
	var actorIDs, techIDs, campaignIDs []string
	err := pool.QueryRow(ctx, `SELECT name, actor_ids, technique_ids, campaign_ids FROM intelligence_tools WHERE id = $1`, id).
		Scan(&name, &actorIDs, &techIDs, &campaignIDs)
	if err == pgx.ErrNoRows {
		return n, nil
	}
	if err != nil {
		return n, err
	}

	toolID := "tool:" + id
	n.Nodes = append(n.Nodes, Node{ID: toolID, Type: NodeTypeTool, Label: name})

	addActors(&n, toolID, actorIDs, "uses")
	if err := addTechniques(ctx, pool, &n, toolID, techIDs); err != nil {
		return n, err
	}
	if err := addCampaigns(ctx, pool, &n, toolID, campaignIDs, "used_in"); err != nil {
		return n, err
	}
	return n, nil
}

// Lookup dispatches to the right assembly function by node type -- the
// single entry point internal/api's handler calls. Named Lookup rather
// than Neighborhood since a package-level function can't share an
// identifier with the Neighborhood type it returns.
func Lookup(ctx context.Context, pool *pgxpool.Pool, nodeType, id string) (Neighborhood, error) {
	switch nodeType {
	case NodeTypeActor:
		return ActorNeighborhood(ctx, pool, id)
	case NodeTypeCampaign:
		return CampaignNeighborhood(ctx, pool, id)
	case NodeTypeMalware:
		return MalwareNeighborhood(ctx, pool, id)
	case NodeTypeTool:
		return ToolNeighborhood(ctx, pool, id)
	case NodeTypeTechnique:
		return TechniqueNeighborhood(ctx, pool, id)
	default:
		return Neighborhood{}, fmt.Errorf("unknown node type %q", nodeType)
	}
}
