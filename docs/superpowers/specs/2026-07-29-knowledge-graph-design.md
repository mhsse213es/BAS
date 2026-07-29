# Knowledge Graph (Threat Intelligence Relationship API) — Design

**Status:** Draft for review
**Author:** Claude + user, brainstormed 2026-07-29. User supplied the core design (node/edge model, assemble-at-request-time principle, separation from `internal/attackpath`, consumer use cases) in free text; this spec translates it into this codebase's concrete conventions.
**Depends on:** [[Intelligence Expansion]] Phases 1, 2, 4, 5 (`internal/intelligence` — `Campaign`/`Malware`/`Tool`, now cross-provider-reconciled), `threat_actor_profiles` (`internal/connector`), `attackdata.GroupTechniqueIndex()` (`internal/reporting/attackdata`).

## Problem

The relationships this feature needs to expose already exist, scattered across four separate places with no unified read path:
- `threat_actor_profiles` (actor ↔ sectors/regions)
- `intelligence_campaigns`/`intelligence_malware`/`intelligence_tools` (actor ↔ campaign/malware/tool, and each of those ↔ techniques, via `ThreatActorIDs`/`TechniqueIDs`/`CampaignIDs` array fields)
- `attackdata.GroupTechniqueIndex()` (actor ↔ technique — a bundled MITRE ATT&CK STIX index, `map[string][]string` keyed by canonical group name, already used by `internal/api/coverage_handlers.go`, `internal/api/ti_handlers.go`, and `internal/connector/otx.go`)

Every consumer that wants "what's connected to this actor/campaign/technique" today has to know all four of these sources and assemble the join itself. The Knowledge Graph is a single read path that does this assembly once, exposed as a graph-shaped API.

## Non-Goals

- **No new storage, no graph database.** Every node/edge is assembled at request time from existing tables/indexes. No synchronization problem, nothing to keep in sync.
- **No whole-graph dump endpoint.** Every real consumer example (Actor page, Technique page, future Purple Team planning) starts from one entity and wants its neighborhood, not the entire graph. A bulk endpoint is deferred until a real consumer needs it — building it now would be speculative.
- **No free-text search.** `GET /api/knowledge-graph/{type}/{id}` takes an explicit type and ID, never a search string. A future search feature (not this phase) resolves a free-text query like "Emotet" to `malware:emotet` first, then calls this API — search and graph-traversal are different concerns, kept separate per the user's own layering diagram (Repository → Knowledge Graph API → {Threat Pages, Search, Purple Team, Reports, future Graph UI}).
- **No UI.** This is API-only. A visualization is a future, separate consumer of this API, not part of this deliverable.
- **Not merged with `internal/attackpath`.** That package models a different domain (network lateral-movement paths — hosts/users/sessions/ACLs, answering "how could an attacker move?"). This package answers "who uses what?" — same `Node`/`Edge`-shaped vocabulary is a coincidence of both being graphs, not a reason to share code. Kept as a fully separate package (`internal/threatgraph`); Go has no naming conflict since they're different packages.
- **No `intrusion_set` node type separate from `actor`.** This codebase already merges OpenCTI's `intrusionSets` into the same `ThreatActor`/`threat_actor_profiles` representation as `threatActors` (Intelligence Expansion Phase 2's `MergeActors`) — there is no separate "intrusion set" entity anywhere in this codebase to expose as a distinct node type.
- **No reverse-index caching for the technique-centered query.** `GroupTechniqueIndex()` is a small, already-cached (`sync.Once`) forward map (actor name → technique IDs); a technique-centered lookup does a linear scan over it. At this codebase's realistic scale (hundreds of groups, not tens of thousands) this is fast enough — building and maintaining a second cached reverse index is premature optimization for a feature with no traffic yet.

## Architecture

### 1. Package: `internal/threatgraph`

Two files, following this codebase's small-focused-file convention:

- `types.go` — `Node`, `Edge`, `Neighborhood` types, node-type constants.
- `assemble.go` — one assembly function per node type, plus a single dispatcher.

```go
package threatgraph

type Node struct {
	ID    string `json:"id"`    // "<type>:<key>" -- e.g. "actor:apt29", "technique:T1059.001"
	Type  string `json:"type"`  // one of the NodeType* constants below
	Label string `json:"label"` // human-readable name
}

type Edge struct {
	From         string `json:"from"`
	To           string `json:"to"`
	Relationship string `json:"relationship"` // "uses" | "attributed_to" | "targets"
}

// Neighborhood is one center node plus everything directly (1-hop) connected
// to it. Center is always Nodes[0].
type Neighborhood struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

const (
	NodeTypeActor     = "actor"
	NodeTypeCampaign  = "campaign"
	NodeTypeMalware   = "malware"
	NodeTypeTool      = "tool"
	NodeTypeTechnique = "technique"
	NodeTypeSector    = "sector"
	NodeTypeRegion    = "region"
)
```

**Node ID scheme**: `"<type>:<key>"`. For actor/sector/region, `<key>` is `intelligence.NormalizeKey(name)` (reused from Intelligence Expansion Phase 5 — same stable-key convention already applied to Campaign/Malware/Tool). For campaign/malware/tool, `<key>` is the entity's own `.ID` field directly (already `NormalizeKey`-based, no double-normalization). For technique, `<key>` is the technique ID as-is, uppercased (e.g. `T1059.001` — already a stable identifier, `techniques.technique_id` is its primary key).

### 2. Assembly functions — one per node type, each queries only what that node type needs

```go
// ActorNeighborhood assembles the 1-hop neighborhood around a threat actor:
// its techniques (attackdata.GroupTechniqueIndex(), keyed by canonical
// actor name), campaigns/malware/tools that list it in their
// ThreatActorIDs, and its sectors/regions (threat_actor_profiles).
func ActorNeighborhood(ctx context.Context, pool *pgxpool.Pool, name string) (Neighborhood, error)

// CampaignNeighborhood assembles the 1-hop neighborhood around a campaign:
// its own ThreatActorIDs and TechniqueIDs.
func CampaignNeighborhood(ctx context.Context, pool *pgxpool.Pool, id string) (Neighborhood, error)

// MalwareNeighborhood assembles the 1-hop neighborhood around a malware
// family: its own ThreatActorIDs, TechniqueIDs, and CampaignIDs.
func MalwareNeighborhood(ctx context.Context, pool *pgxpool.Pool, id string) (Neighborhood, error)

// ToolNeighborhood mirrors MalwareNeighborhood exactly (same field shape).
func ToolNeighborhood(ctx context.Context, pool *pgxpool.Pool, id string) (Neighborhood, error)

// TechniqueNeighborhood assembles the 1-hop neighborhood around a
// technique: every actor whose GroupTechniqueIndex() entry contains it,
// plus every campaign/malware/tool whose TechniqueIDs contains it
// (three separate `technique_id = ANY(technique_ids)` queries).
func TechniqueNeighborhood(ctx context.Context, pool *pgxpool.Pool, techniqueID string) (Neighborhood, error)

// Neighborhood dispatches to the right assembly function by node type --
// the single entry point internal/api's handler calls.
func Neighborhood(ctx context.Context, pool *pgxpool.Pool, nodeType, id string) (Neighborhood, error)
```

Each `*Neighborhood` function issues a small, fixed number of already-indexed queries (primary-key lookups on `intelligence_campaigns`/`malware`/`tools`, array-membership scans via `ANY(...)` on their `actor_ids`/`technique_ids`/`campaign_ids` columns, plus a `threat_actor_profiles` lookup by primary key `name`) — no new indexes needed, these array columns are the same ones Phase 1-5 already query.

### 3. API — `GET /api/knowledge-graph/{type}/{id}`

```go
// GET /api/knowledge-graph/{type}/{id}
func (h *Handler) KnowledgeGraphNeighborhood(w http.ResponseWriter, r *http.Request) {
	nodeType := chi.URLParam(r, "type")
	id := chi.URLParam(r, "id")
	n, err := threatgraph.Neighborhood(r.Context(), h.db, nodeType, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, n)
}
```

An unrecognized `type` (not one of the 5 queryable types — `sector`/`region` are edge-target-only, never a valid `{type}` path segment since nothing queries "what's connected to this sector") or a `type`/`id` combination that resolves to zero nodes returns a `Neighborhood{Nodes: [], Edges: []}` with `200 OK`, not a `404` — consistent with `ListCampaigns`/`ListMalware`/`ListTools`'s existing "always return an empty slice, not an error" convention for "found nothing" cases in this codebase. An actually-invalid `type` string (not one of the 5) returns `400 Bad Request`.

Registered `tierAny`, RBAC entry added in the same commit — this project's established habit for every `internal/intelligence`-adjacent route this session.

## Testing

- `internal/threatgraph`: one test per assembly function, hand-seeding a real Postgres test DB (`testutil.TestDB`, matching `internal/intelligence`'s existing convention) with one actor + one campaign + one malware + one tool + known `TechniqueIDs`/`ThreatActorIDs`/`CampaignIDs` overlap, then asserting the resulting `Neighborhood`'s node/edge counts and specific IDs/relationships. `TestActorNeighborhood_IncludesTechniquesFromGroupTechniqueIndex` needs a real ATT&CK group name (`attackdata.GroupTechniqueIndex()` is bundled, real data — pick a group confirmed present, e.g. one already used in existing `internal/connector/otx_test.go` fixtures, to avoid guessing at bundled data that might not exist).
- `TestNeighborhood_UnknownTypeReturnsError` — dispatcher rejects an invalid type string.
- `TestNeighborhood_UnknownIDReturnsEmptyNeighborhood` — a well-formed type with a nonexistent ID returns `{Nodes: [], Edges: []}`, not an error (matches the "empty slice, not error" convention above).
- `internal/api`: RBAC matrix entry for `GET /api/knowledge-graph/{type}/{id}`, matching the existing `rbac_matrix_test.go` pattern.
- Full regression (`go build ./...`, `go vet ./...`, `go test ./... -count=1`) as the closing task.
