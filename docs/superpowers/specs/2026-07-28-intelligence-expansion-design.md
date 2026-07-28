# Intelligence Expansion (Phase 1: MISP Campaigns + Malware) — Design

**Status:** Draft for review
**Author:** Claude + user, brainstormed 2026-07-28
**Depends on:** none new — extends `internal/connector`'s existing MISP client

## Problem

The user's original "Intelligence Repository" vision (Actors/Campaigns/Malware/Tools/IOCs/CVEs/Reports, all normalized) turned out to be ~70% already built under different names: `threat_actor_profiles` is the Actor entity, `ioc_enrichment` (`internal/ioc`) is the IOC entity, `cves` + `technique_cve_relationships` (the Relationship Store) is the CVE/vulnerability model. Building a new normalized schema over all of that would duplicate mature code for no payoff.

The real gap: **Campaigns and Malware have no representation anywhere**, and MISP's connector already fetches data that would populate them — `Event.GalaxyCluster` (malware/intrusion-set clusters, not just ATT&CK techniques) and the MISP event itself (a natural campaign container) — but today the code filters this down to *only* `mitre-attack-pattern` entries and discards the rest after fetching it.

This project stops discarding that data. It's explicitly Phase 1 of 5 (per the user's roadmap): MISP-only now; OpenCTI extended in Phase 2; Google TI/Mandiant in Phase 3; Tools in Phase 4; the *true* normalized Intelligence Repository only in Phase 5, once multiple providers contribute overlapping Campaign/Malware data and normalization starts paying for itself.

## Non-Goals

- **Not** a new normalized "Repository" schema — no relationship/join tables, no Actor↔Campaign↔Malware↔Tool graph. Entities carry denormalized ID-list fields (`ThreatActorIDs`, `TechniqueIDs`) and get normalized only in Phase 5, once there's more than one source to reconcile.
- **Not** touching OpenCTI or OTX — their `Fetch()` implementations are unchanged. Only `MISPClient` gains new extraction logic.
- **Not** a UI surface this phase — read API only, so the data is verifiable and usable by future work, but no new tab.
- **Not** capturing MISP's raw IOC `Attribute` data (IPs/hashes/domains/URLs) — that already has a home in `internal/ioc` + `ioc_enrichment`. This project only captures `GalaxyCluster` malware/intrusion-set data and the event-as-campaign container.
- **Not** inventing fields STIX/MISP could theoretically support but nothing here actually populates — e.g. no `Families` field on Malware (no current data source distinguishes "family" from "alias"); no numeric confidence scale (kept on the existing `high`/`medium`/`low` string convention every other actor/intel record already uses).

## Architecture

New flat package `internal/intelligence` (matches every other package in this codebase — `internal/connector`, `internal/coverage`, `internal/threatpriority` are all flat, no nested subpackages) holds the `Campaign`/`Malware`/`SourceRef` types and their persistence (free functions taking `ctx, pool` per call, matching `internal/reporting.ResolveActorTechniques`'s shape — no stateful wrapper struct, since there's no state to hold beyond the pool itself).

`internal/connector` imports `internal/intelligence` for these types (one-directional, no cycle — `intelligence` never imports `connector`, same discipline `internal/threatpriority` already established for the same reason).

### Data model

```go
// internal/intelligence/models.go
package intelligence

import (
	"strings"
	"time"
)

// SourceRef is provenance metadata carried by every Campaign/Malware record.
// Exists from day one so Phase 5's multi-provider reconciliation has a
// mechanism already in place rather than requiring a schema redesign when
// OpenCTI/Google TI start contributing the same entities.
type SourceRef struct {
	Provider    string    // "misp" (only value through Phase 1)
	ExternalID  string    // MISP event ID (Campaign) / galaxy cluster value (Malware)
	LastUpdated time.Time
	Confidence  string    // "high" | "medium" | "low" | "" — same convention as
	                      // connector.ThreatActor.Confidence and
	                      // threatpriority.ConfidenceFactor, not a new numeric scale
}

// Campaign is one MISP event that qualified as ATT&CK-relevant (the same
// gate connector.MISPClient already applies for actor extraction). The
// event itself is the campaign container — MISP doesn't expose a distinct
// "campaign" galaxy type separate from its events in what this client
// already parses.
type Campaign struct {
	ID             string // = Source.ExternalID for MISP (event ID, already unique)
	Name           string
	Description    string
	ThreatActorIDs []string // threat_actor_profiles.name values
	TechniqueIDs   []string
	Source         SourceRef
}

// Malware is one mitre-malware GalaxyCluster entry, deduplicated by
// normalized name across every event that references it (MalwareKey).
type Malware struct {
	ID             string // = MalwareKey(Name) — cross-event dedup key
	Name           string
	Aliases        []string
	TechniqueIDs   []string
	ThreatActorIDs []string
	CampaignIDs    []string
	Source         SourceRef
}

// MalwareKey normalizes a malware name into a stable dedup key -- same
// normalization connector.actorKey() already applies to actor names
// (lowercase, strip spaces/hyphens), duplicated here rather than exported
// from internal/connector to avoid connector<->intelligence coupling in
// either direction beyond the one-way types import.
func MalwareKey(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	return s
}
```

### Persistence

```sql
-- added to internal/db/content_schema.go's EnsureContentSchema stmts
CREATE TABLE IF NOT EXISTS intelligence_campaigns (
	id                  text        PRIMARY KEY,
	name                text        NOT NULL,
	description         text        NOT NULL DEFAULT '',
	actor_ids           text[]      NOT NULL DEFAULT '{}',
	technique_ids       text[]      NOT NULL DEFAULT '{}',
	source_provider     text        NOT NULL,
	source_external_id  text        NOT NULL DEFAULT '',
	source_confidence   text        NOT NULL DEFAULT '',
	last_updated        timestamptz NOT NULL DEFAULT NOW(),
	tenant_id           text        NOT NULL DEFAULT 'default'
)

CREATE TABLE IF NOT EXISTS intelligence_malware (
	id                  text        PRIMARY KEY,
	name                text        NOT NULL,
	aliases             text[]      NOT NULL DEFAULT '{}',
	technique_ids       text[]      NOT NULL DEFAULT '{}',
	actor_ids           text[]      NOT NULL DEFAULT '{}',
	campaign_ids        text[]      NOT NULL DEFAULT '{}',
	source_provider     text        NOT NULL,
	source_external_id  text        NOT NULL DEFAULT '',
	source_confidence   text        NOT NULL DEFAULT '',
	last_updated        timestamptz NOT NULL DEFAULT NOW(),
	tenant_id           text        NOT NULL DEFAULT 'default'
)
```

`tenant_id` included from creation (not bolted on later), matching every table added since the multi-tenancy work started.

```go
// internal/intelligence/store.go
package intelligence

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// UpsertCampaign overwrites on conflict — each MISP event ID is already
// unique, so re-syncing the same event is a plain refresh, no merge needed.
func UpsertCampaign(ctx context.Context, pool *pgxpool.Pool, c Campaign) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO intelligence_campaigns
		   (id, name, description, actor_ids, technique_ids, source_provider, source_external_id, source_confidence, last_updated)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (id) DO UPDATE SET
		   name = EXCLUDED.name, description = EXCLUDED.description,
		   actor_ids = EXCLUDED.actor_ids, technique_ids = EXCLUDED.technique_ids,
		   source_provider = EXCLUDED.source_provider, source_external_id = EXCLUDED.source_external_id,
		   source_confidence = EXCLUDED.source_confidence, last_updated = EXCLUDED.last_updated`,
		c.ID, c.Name, c.Description, c.ThreatActorIDs, c.TechniqueIDs,
		c.Source.Provider, c.Source.ExternalID, c.Source.Confidence, c.Source.LastUpdated)
	return err
}

// UpsertMalware merges on conflict — the same malware family is legitimately
// referenced by many different events, so technique/actor/campaign ID lists
// accumulate (deduplicated union) rather than overwrite.
func UpsertMalware(ctx context.Context, pool *pgxpool.Pool, m Malware) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO intelligence_malware
		   (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider, source_external_id, source_confidence, last_updated)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 ON CONFLICT (id) DO UPDATE SET
		   aliases       = ARRAY(SELECT DISTINCT UNNEST(intelligence_malware.aliases || EXCLUDED.aliases)),
		   technique_ids = ARRAY(SELECT DISTINCT UNNEST(intelligence_malware.technique_ids || EXCLUDED.technique_ids)),
		   actor_ids     = ARRAY(SELECT DISTINCT UNNEST(intelligence_malware.actor_ids || EXCLUDED.actor_ids)),
		   campaign_ids  = ARRAY(SELECT DISTINCT UNNEST(intelligence_malware.campaign_ids || EXCLUDED.campaign_ids)),
		   source_confidence = EXCLUDED.source_confidence,
		   last_updated  = GREATEST(intelligence_malware.last_updated, EXCLUDED.last_updated)`,
		m.ID, m.Name, m.Aliases, m.TechniqueIDs, m.ThreatActorIDs, m.CampaignIDs,
		m.Source.Provider, m.Source.ExternalID, m.Source.Confidence, m.Source.LastUpdated)
	return err
}

func ListCampaigns(ctx context.Context, pool *pgxpool.Pool) ([]Campaign, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, name, description, actor_ids, technique_ids, source_provider, source_external_id, source_confidence, last_updated
		 FROM intelligence_campaigns ORDER BY last_updated DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Campaign{}
	for rows.Next() {
		var c Campaign
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.ThreatActorIDs, &c.TechniqueIDs,
			&c.Source.Provider, &c.Source.ExternalID, &c.Source.Confidence, &c.Source.LastUpdated); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func ListMalware(ctx context.Context, pool *pgxpool.Pool) ([]Malware, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider, source_external_id, source_confidence, last_updated
		 FROM intelligence_malware ORDER BY last_updated DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Malware{}
	for rows.Next() {
		var m Malware
		if err := rows.Scan(&m.ID, &m.Name, &m.Aliases, &m.TechniqueIDs, &m.ThreatActorIDs, &m.CampaignIDs,
			&m.Source.Provider, &m.Source.ExternalID, &m.Source.Confidence, &m.Source.LastUpdated); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
```

No pagination/limit param in Phase 1 — MISP-only volume is small; add one later if a real volume problem shows up (YAGNI).

### MISP extraction

`connector/source.go` gains a third optional capability interface, alongside the two (`StatsSource`, and the `*BundleSource` type-assertion) `Scheduler.sync()` already type-asserts against:

```go
// IntelligenceSource is an optional Source capability: providers that can
// also extract Campaign/Malware intelligence beyond actor-technique
// profiles implement this. Only MISPClient does through Phase 1 of
// docs/superpowers/specs/2026-07-28-intelligence-expansion-design.md;
// OpenCTI/OTX/Bundle are unaffected until later phases extend them.
type IntelligenceSource interface {
	FetchIntelligence() ([]intelligence.Campaign, []intelligence.Malware, error)
}
```

`MISPClient` gains `lastCampaigns []intelligence.Campaign` / `lastMalware []intelligence.Malware` fields, populated during `Fetch()`'s existing per-event loop (not a second MISP query) and returned by `FetchIntelligence()` — the exact same after-the-fact-accessor pattern `StatsSource.Stats()` already uses for `lastStat`.

`Fetch()`'s loop is restructured minimally: the `hasMitre` pre-filter and the `getEvent()` call move out of `extractActor` into `Fetch()` itself, so the fetched `detail` can be shared with a new sibling function rather than fetched twice per event:

```go
// extractActor(ev, detail) — signature changes to accept pre-fetched detail;
// body unchanged otherwise (tag parsing, GalaxyCluster technique extraction,
// mitre-attack-pattern attribute extraction, dedup, LastSeen).

// extractIntelligence builds Phase 1 data from an already-qualified,
// already-fetched event and its extracted actor -- reuses actor.Name and
// actor.Techniques rather than re-deriving them. One Campaign per
// qualifying event. Zero or more Malware records, one per mitre-malware
// GalaxyCluster entry. Malware entries inherit the SAME technique/actor
// association as the event's actor -- MISP's flat galaxy list doesn't
// support finer per-malware technique attribution without deeper
// relationship parsing, which Phase 1 deliberately doesn't attempt.
func (c *MISPClient) extractIntelligence(ev mispEventIndex, detail *mispEventDetail, actor *ThreatActor) (*intelligence.Campaign, []intelligence.Malware) {
	src := intelligence.SourceRef{
		Provider: "misp", ExternalID: ev.ID,
		LastUpdated: actor.LastSeen, Confidence: actor.Confidence,
	}
	if src.LastUpdated.IsZero() {
		src.LastUpdated = time.Now()
	}

	campaign := &intelligence.Campaign{
		ID: ev.ID, Name: detail.Event.Info, Description: detail.Event.Info,
		ThreatActorIDs: []string{actor.Name}, TechniqueIDs: techniqueIDs(actor.Techniques),
		Source: src,
	}

	var malware []intelligence.Malware
	for _, gc := range detail.Event.GalaxyCluster {
		if gc.Type != "mitre-malware" {
			continue
		}
		name := strings.TrimSpace(gc.Value)
		if name == "" {
			continue
		}
		malware = append(malware, intelligence.Malware{
			ID: intelligence.MalwareKey(name), Name: name,
			TechniqueIDs: techniqueIDs(actor.Techniques),
			ThreatActorIDs: []string{actor.Name}, CampaignIDs: []string{ev.ID},
			Source: src,
		})
	}
	return campaign, malware
}

func techniqueIDs(techs []TechniqueRef) []string {
	ids := make([]string, 0, len(techs))
	for _, t := range techs {
		ids = append(ids, t.ID)
	}
	return ids
}

func (c *MISPClient) FetchIntelligence() ([]intelligence.Campaign, []intelligence.Malware, error) {
	return c.lastCampaigns, c.lastMalware, nil
}
```

`mitre-malware` as the `GalaxyCluster.Type` value is grounded in the same MISP galaxy taxonomy the existing code already relies on for `mitre-attack-pattern` (techniques) and `misp-galaxy:mitre-intrusion-set=` (actor names, a live tag prefix in this exact codebase today) — not independently verified against a live MISP instance, same honesty standard as the existing `OpenCTIClient.sectors` comment already applies to an unverified OpenCTI assumption.

### Scheduler wiring

`Scheduler.sync()`'s existing per-source loop (`internal/connector/scheduler.go`) gains one more type-assertion, in the same place `StatsSource`/`*BundleSource` already are:

```go
for _, src := range s.sources {
	got, err := src.Fetch()
	if ss, ok := src.(StatsSource); ok {
		bySource[src.Name()] = ss.Stats()
	}
	if err != nil { /* unchanged */ }
	actors = append(actors, got...)
	if bs, ok := src.(*BundleSource); ok {
		bundleVersion = bs.Version()
	}
	if is, ok := src.(IntelligenceSource); ok {
		campaigns, malware, ierr := is.FetchIntelligence()
		if ierr != nil {
			log.Printf("[connector/%s] intelligence fetch error: %v", src.Name(), ierr)
		} else {
			allCampaigns = append(allCampaigns, campaigns...)
			allMalware = append(allMalware, malware...)
		}
	}
}
```

Persisted right after `s.upsertActorProfiles(actors)` (same nil-pool discipline everything else in `sync()` already follows):

```go
if s.pool != nil {
	for _, c := range allCampaigns {
		if err := intelligence.UpsertCampaign(context.Background(), s.pool, c); err != nil {
			log.Printf("[connector] upsert campaign %q: %v", c.ID, err)
		}
	}
	for _, m := range allMalware {
		if err := intelligence.UpsertMalware(context.Background(), s.pool, m); err != nil {
			log.Printf("[connector] upsert malware %q: %v", m.ID, err)
		}
	}
}
```

## API

Two new read-only (`tierAny`, matching every other `/api/ti/*` and `/api/coverage/*` route) endpoints in a new `internal/api/intelligence_handlers.go`:

```
GET /api/intelligence/campaigns  → []intelligence.Campaign
GET /api/intelligence/malware    → []intelligence.Malware
```

No new `Handler` field or `With*` wiring needed — unlike `internal/threatpriority.Engine` (which holds config/state), `internal/intelligence`'s functions take `h.db` directly, so the handlers call `intelligence.ListCampaigns(r.Context(), h.db)` / `intelligence.ListMalware(r.Context(), h.db)` inline. `main.go` needs no changes at all for this project — the MISP source is already constructed and wired into the Scheduler; it just does more during `sync()` now.

Route registration in `routes.go`, near the other Threat Intelligence routes:

```go
r.Get("/api/intelligence/campaigns", h.IntelligenceCampaigns)
r.Get("/api/intelligence/malware", h.IntelligenceMalware)
```

Plus the corresponding `routeMatrix` entries in `rbac_matrix_test.go` (`tierAny`), added in the same task that adds the routes.

## Testing

- `internal/intelligence`: unit tests for `MalwareKey` (normalization cases), DB-backed tests for `UpsertCampaign` (insert + overwrite-on-conflict), `UpsertMalware` (insert + union-merge-on-conflict across two upserts with overlapping and non-overlapping IDs), `ListCampaigns`/`ListMalware` (empty + populated).
- `internal/connector`: `MISPClient.extractIntelligence` unit tests against hand-built `mispEventIndex`/`mispEventDetail` fixtures — one Campaign extracted correctly, zero Malware when no `mitre-malware` cluster present, multiple Malware entries when multiple clusters present, `FetchIntelligence()` returns what `Fetch()` populated (mirrors how `Stats()` is already tested). `Scheduler.sync()` test extended to confirm campaigns/malware end up persisted when a `IntelligenceSource`-implementing fake is used (or MISPClient itself, container-backed).
- `internal/api`: handler tests for both new endpoints (empty case, populated case), `rbac_matrix_test.go` updated in the same task that adds the routes.
- Full regression (`go test ./... -count=1`, `go build ./...`, `go vet ./...`) as the final plan task.
