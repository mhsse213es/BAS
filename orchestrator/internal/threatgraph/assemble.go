package threatgraph

import (
	"context"
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
