# TCF Phase 2 — Canonical Threat, Evidence, Trust and TCV

**Status:** design approved conversationally 2026-10-06; this document awaits written review.
**Builds on:** Phase 1 Content Registry (`2026-10-04-tcf-phase1-content-registry-design.md`, merged to main as `42c6026d`).
**Delivery:** one spec, three milestones — **2A → 2B → 2C** — each with its own plan and review gates.

## 1. Purpose

Phase 1 made executable content governed: every run is tied to an immutable, trusted content version. It did not give the factory a stable thing to produce content *for*. Today the intel path is:

```
MISP / OpenCTI / bundle → name-keyed actor records → generator (intel-<sha256(lower(name))[:12]>)
```

so a rename or alias canonicalization forks content identity, technique attributions carry no history, and Threat Coverage Velocity (TCV) cannot be computed.

Phase 2 delivers:

```
sources → immutable source evidence → canonical Threat (stable identity)
        → materialized technique state → content linked to Threat → TCV
```

**Layering (each layer depends only on those to its left):**
identity → evidence → source trust → confidence → current projection → generation policy.

### 1.1 Out of scope

- New feeds (CISA, CERT-In). Once this model exists they are adapters.
- Validation lab / sandbox, safety classifier, distribution (later phases).
- Rewriting campaign / malware / tool entity resolution (their `search_key` merge stays as shipped).
- Dashboard UI for the unresolved queue (API only; UI consumes it later).
- Correction / reversal of terminal admin resolution decisions (future, explicit mechanism).
- Coverage continuity / freshness / revocation metrics (distinct from TCV; not built here).

### 1.2 Deployment precondition

Phase 1 stays **undeployed** until milestone 2A is implemented, if operationally feasible, so the content-ID switch (§4) costs nothing. §4.4 states what happens if that does not hold.

## 2. Code facts this design is grounded in

| Fact | Where | Consequence |
|---|---|---|
| `threat_actor_profiles.name` is the PRIMARY KEY; `threat_actor_sources`, `threat_actor_activity`, `technique_evidence` FK to it by `actor_name` | `db/postgres.go:1342`, `db/content_schema.go:422-485` | Identity migration needed, not `ADD COLUMN id` |
| `intelligence_campaigns/malware/tools.actor_ids text[]` hold actor **names** | `db/content_schema.go:282-320` | Campaign→actor relation must migrate to `actor_id` |
| Intel content id = `intel-` + 12 hex of sha256(lowercased **name**) | `connector/generator.go:372` | Replaced by §4 |
| MISP and OpenCTI drop actors with < 2 techniques before merge | `misp.go:87`, `opencti.go:69` | Must move downstream of the evidence boundary (§6.2) |
| MISP: `/events/index` unpaged; a failed per-event detail fetch is logged and **skipped** | `misp.go:61-83` | Such a sync is `partial` |
| OpenCTI: GraphQL `first: 100`, no `pageInfo` / cursor pagination | `opencti.go:269-411` | A sync returning exactly 100 at any level is `truncated` |
| OTX: ≤ 10 pages × 50; later-page failure returns partial data **plus** an error; produces only **activity signals**, never technique claims or actors | `otx.go:13-21, 75-100` | OTX is an `activity_window` source |
| MISP confidence is free text from a `confidence:` tag; OpenCTI is integer 0-100; bundle/OTX have none | `misp.go:238`, `opencti.go:150` | Closed per-source mapping (§7.3) |
| Builtin kill chains name their actor only in free text (e.g. `apt29-kill-chain.yaml`) | `scenarios/*.yaml` | Signed structured `emulates` metadata (§9.2) |
| The gate is evaluated only at dispatch; nothing records "became executable" | `contentregistry/gate.go:26` | `first_executable_at` written at transitions (§10.3) |
| Executable combos: VENDOR+VENDOR_SIGNED+PUBLISHED, LOCAL+LOCAL_TRUSTED+PUBLISHED_LOCAL, dev-only VENDOR+UNTRUSTED+PUBLISHED | `contentregistry` `Executable()` | Dev-only combo never stops a TCV clock |

## 3. Identity (milestone 2A)

### 3.1 Actor identity

- `threat_actor_profiles` gains `id text` — an **immutable Audspect actor id**, `act-<uuid>` (lowercase, opaque, assigned once, never derived from a name). It becomes the primary key.
- `name` is the current display name. It is **not unique forever**. During Phase 2 a uniqueness constraint on `name` may remain as an *ingestion constraint* for legacy name-keyed readers; it is not an identity invariant and must not be relied on by new code.
- `canonical_group_id` (MITRE `G####`) is an **external identity attribute**, nullable. Actors without a MITRE mapping still have a valid id. A changed G-ID mapping never changes the actor id.
- `aliases` are mutable resolution/display data.

**Identity migration.** Every existing profile gets a new id; its current name becomes the initial display name. Legacy child tables (`threat_actor_sources`, `threat_actor_activity`, `technique_evidence`) gain an `actor_id` column backfilled from the name join; their FK moves to `actor_id`; `actor_name` remains as a denormalized display column so existing readers keep working. Renames therefore no longer cascade through name FKs.

### 3.2 Threat

```
threats
  id             text PK          -- thr-<uuid>, immutable
  subject_type   text NOT NULL    -- CHECK IN ('actor','campaign','malware','tool')
  subject_id     text NOT NULL    -- for 'actor': threat_actor_profiles.id
  title          text NOT NULL    -- display only
  summary        text NOT NULL DEFAULT ''
  first_seen_at  timestamptz NULL -- projection; §7.4
  last_seen_at   timestamptz NULL
  status         text NOT NULL    -- 'active' | 'inactive'
  created_at     timestamptz NOT NULL
  UNIQUE (subject_type, subject_id)
```

- **One Threat = exactly one canonical subject.** There is no separate `kind`.
- Threat is the factory's normalized unit of threat relevance; it is not a synonym for an ATT&CK group, campaign, malware, or IOC. Those entities keep their own tables.
- The schema allows all four subject types; **Phase 2 populates `actor` only**. An FK from `subject_id` to `threat_actor_profiles(id)` is enforced for actor rows (partial FK via a generated `actor_subject_id` column, `CASE subject_type WHEN 'actor' THEN subject_id END`).
- `status` is a projection, recomputed with `threat_techniques` (§7): `active` while the threat has at least one active technique or a current observation from a trusted source; otherwise `inactive`. It never deletes or re-identifies the Threat, and it never feeds a TCV clock.
- Threats are created only for **resolved** actors. An unresolved record never produces a Threat or content.

### 3.3 Resolver and deduplication

Incoming source records resolve to an actor in this **deterministic** order; the first rule that yields exactly one actor wins:

1. Existing canonical entity id (a source record already linked by a prior resolution or admin decision).
2. Provider's stable external identity (`source_instance` + `external_id`) previously mapped.
3. Strong ATT&CK identity (`G####` resolved through `attackdata.GroupByID`).
4. Carefully normalized aliases (existing token logic in `actor_merge.go`) — **only** when it yields exactly one actor.
5. Name similarity — **never merges**; produces a review candidate only.

Zero matches with no ambiguity → a new actor id + new Threat. More than one possible actor, or a rule-5 match → **unresolved**. Alias matching is one signal of the resolver, not the definition of identity. Rename detection must never create a new actor.

### 3.4 Unresolved queue (admin API)

```
actor_resolution_candidates
  id, source_instance_id, external_id, raw_name, reason,
  resolver_context_hash,         -- sha256 of a canonical JSON snapshot of what the resolver saw
  resolver_context    jsonb,     -- the snapshot itself (candidate actor ids, matched tokens, rule)
  status              -- 'unresolved' | 'linked' | 'new_actor' | 'dismissed'
  decided_by, decided_at, decision_reason, created_at
```

`POST /api/intel/actor-resolutions/{id}` with `{"action":"link","actorId":...}`, `{"action":"new"}`, or `{"action":"dismiss"}`; `decisionReason` is required. Admin-only, audited.

- **link:** validates the actor exists and is current; the decision itself is the authoritative resolution event (fuzzy matching is not rerun). The source identity is mapped to the actor for future syncs.
- **new:** creates a new immutable actor id, profile (raw name as initial display name), Threat, and links the evidence.
- **dismiss:** intentionally unassociated; creates no actor and no Threat; evidence stays intact.
- Decisions are **terminal**; no transition out of `linked`, `new_actor`, or `dismissed`.
- **No time-based auto-resolution** of any kind.
- `GET /api/intel/actor-resolutions?status=unresolved` lists candidates with their context.

### 3.5 Campaign → actor relation

`intelligence_campaigns.actor_ids` (names) migrates to:

```
campaign_actors (campaign_id FK, actor_id FK, PRIMARY KEY (campaign_id, actor_id))
```

through a deterministic name → actor profile → actor_id mapping. Ambiguous or unresolved names are **not** silently converted: they are reported in the migration inventory and enter the unresolved workflow; the original array is retained until a later cleanup. Threat creation does not depend on this migration succeeding. `intelligence_malware/tools.actor_ids` receive the same treatment (`malware_actors`, `tool_actors`). Campaign/malware/tool deduplication behavior is unchanged.

## 4. Intel content identity (milestone 2A)

### 4.1 Rule

Intel content identity is derived from the immutable canonical **threat id**, never from a mutable name, alias, source name, or ATT&CK group name. It is stable across renames, alias changes, and source canonicalization.

### 4.2 Algorithm (fixed, documented, versioned)

```
content_id = "intel-" + lowercase_hex( SHA-256( "audspect/tcf/intel-content-id/v1\x00" + threat_id ) )[0:16]
```

UTF-8 bytes, no normalization of `threat_id` (it is already canonical). The prefix string versions the scheme. The result matches the scenario id pattern `^[a-z0-9][a-z0-9-]{1,63}$`.

### 4.3 Referential integrity

The hash is a representation, not the relationship. The database enforces it: the generator writes a `generated_for` row in `content_version_threats` (§9) for every intel version, and a uniqueness constraint guarantees **one threat per intel content id** (`content_generation_owners (content_id PK, threat_id FK UNIQUE)`). On a hash collision with a different threat, generation for that threat **fails closed** (logged, counted in `GenerateResult.Failed`) rather than appending to another threat's content.

### 4.4 Existing name-derived intel content

| Situation | Decision |
|---|---|
| Phase 1 undeployed | A directly; no legacy ids exist |
| Deployed, no meaningful approval or run history | A with a controlled migration |
| Approved content or customer run history exists | Reassess; option C (stored mapping) may be justified |

The 2A migration handles any `intel-<12 hex>` content found: each old id's actor name is resolved through §3.3. Confident → the threat-derived id gets the next generation as DRAFT, and the old content is retired with reason `superseded by <new id>` **only if it has no approved version and no runs**. Content with approvals or runs is **never touched automatically**; it is listed in the migration inventory for an admin decision. Ambiguous → unresolved queue. Nothing is deleted.

## 5. Evidence model (milestone 2B)

### 5.1 Source instances and trust

```
source_instances
  id, source_type ('bundle'|'misp'|'opencti'|'otx'), display_name,
  observation_mode ('snapshot'|'activity_window'), created_at

source_trust_versions            -- append-only
  id, source_instance_id, trust_state ('trusted'|'untrusted'),
  effective_at, changed_by, reason
```

Defaults, written as the first trust version when an instance is created:

| Source | Default trust | Evidence | Supports active set |
|---|---|---|---|
| Bundled versioned MITRE ATT&CK | trusted | yes | yes |
| Customer-configured MISP | trusted | yes | yes |
| Customer-configured OpenCTI | trusted | yes | yes |
| OTX / community | **untrusted** | yes (visible, auditable) | no, until elevated |

Changing trust is an admin-only, audited action: `POST /api/intel/sources/{id}/trust` with `{"trustState":..., "reason":...}`. Trust is a property of the source instance, independent of claim confidence.

### 5.2 Sync observations

```
source_syncs
  id, source_instance_id, started_at, completed_at,
  status        ('succeeded'|'failed'),
  completeness  ('complete'|'partial'|'truncated'|'failed'),
  authoritative boolean,     -- computed by the evidence layer, see §6.1
  diagnostic    text
```

The **source adapter** determines completeness by the source's own semantics, never by HTTP success alone:

| Source | `complete` only when |
|---|---|
| Bundle | file signature verified and parsed in full |
| MISP | index fetched and **every** qualifying event detail fetched; any skipped detail → `partial` |
| OpenCTI | no connection at any level returned exactly its `first:` limit (until cursor pagination is implemented, that is `truncated`) |
| OTX | never authoritative (`activity_window`); hitting the page cap → `truncated`; later-page error → `partial` |

### 5.3 Source observations and threat sources

```
source_observations                -- append-only, one per source record per sync
  id, sync_id, source_instance_id, external_id, raw_name,
  record_hash, observed_at, raw jsonb,
  trust_version_id                 -- the source's trust version at observed time
  candidate_id NULL                -- set when the record went to the unresolved queue

threat_sources                     -- append-only: links evidence to a Threat
  id, threat_id, observation_id, provider, external_id,
  observed_at, source_confidence, record_hash,
  first_seen_at_generation,        -- first generation that consumed this evidence
  linked_by ('resolver'|'admin'), linked_ref
```

Evidence of unresolved records lives in `source_observations` with no Threat; it is linked through `threat_sources` once resolved. Identical text from two providers is **not** deduplicated away.

## 6. Claims and retractions (milestone 2B)

### 6.1 Rule: absence is not retraction

A technique claim is retracted only by an explicit retraction observation produced by a sync that is `complete` **and** `authoritative` for that source's declared observation model. The evidence layer computes `authoritative = (completeness = 'complete' AND observation_mode = 'snapshot')` and **refuses** to write retractions for any other sync, regardless of what the adapter requests.

| Observation | Absent claim retracts? |
|---|---|
| Complete snapshot | yes |
| Incomplete snapshot (partial / truncated) | no |
| `activity_window` source | no; freshness via `last_seen_at` plus downstream policy |
| Failed sync | no |

### 6.2 Evidence boundary

```
raw source → parse/normalize → SOURCE CLAIMS (boundary) → source-specific policy → merged/current set → generation policy
```

Claims are captured **before** any connector filter. The MISP/OpenCTI ≥ 2-technique minimum moves downstream to generation policy; it can never erase evidence. Per-event MISP claims are recorded per event, not only after the per-source actor merge.

### 6.3 Claim rows

```
technique_claims                    -- append-only
  id, observation_id, sync_id, source_instance_id,
  technique_id, kind ('claim'|'retraction'),
  via, via_name, start_time, stop_time,
  raw_confidence text NULL, normalized_confidence smallint NULL,
  confidence_mapping_version text NULL,
  trust_version_id, observed_at
```

A later source update appends a claim or retraction; nothing is overwritten. When a complete snapshot no longer contains a (subject, technique) that source previously claimed — including when the whole actor is absent — a `retraction` row is written, tied to that sync.

## 7. Projection: `threat_techniques` (milestone 2B)

### 7.1 Shape

```
threat_techniques                   -- materialized; one row per pair; never deleted
  threat_id, technique_id, PRIMARY KEY (threat_id, technique_id),
  first_seen_at,                    -- historical; never moves forward
  last_seen_at,
  supporting_source_count, best_confidence smallint NULL,
  status ('active'|'retracted'),
  status_reason ('supported'|'source_retraction'|'trust_revocation'),
  projected_at
```

### 7.2 Active rule

A technique is **active** when at least one current, non-retracted claim from a source that is **trusted now** supports it. "Current" means the latest claim/retraction row for (source instance, threat, technique) is a claim. Confidence is recorded but **never** used as an implicit threshold. Confidence, recency, and the 2-technique minimum are explicit downstream policies.

### 7.3 Confidence normalization

Raw is preserved; normalization to 0-100 uses an explicit, versioned per-source mapping. OpenCTI integer → itself. MISP free text → a closed documented table (e.g. MISP `confidence-level` taxonomy values); unrecognized → NULL. Bundle and OTX → raw NULL, normalized NULL. No invented 100. `best_confidence` = max of non-null normalized values among current supporting claims.

### 7.4 Trust and history

- Each claim references the `trust_version_id` in force at `observed_at`. "Was this source trusted when this was observed?" is answered from history, never from current configuration.
- **first_seen_at** = min `observed_at` over claims observed under a *trusted* trust version. Trust granted later does not backdate it: an OTX claim observed while untrusted never counts toward `first_seen_at`, even after OTX is trusted.
- **Granting trust** makes the source's existing current claims count toward the *active* set from `effective_at`. If such a pair has no claim observed under trust yet, it is active with `first_seen_at = NULL` until the next trusted observation sets it. (Resolution of the example "untrusted claim Jan 1, trusted Mar 1, claimed again Apr 1 → first trusted attribution Apr 1".)
- **Revoking trust** removes the source's claims from current support from `effective_at`; historical evidence remains valid.
- Two distinct causes may make a row `retracted`, kept distinguishable in `status_reason` and the audit trail: **source retraction** and **trust revocation**.

The projection is recomputed for affected threats after every sync and every trust change, inside the same transaction that wrote the triggering rows.

## 8. Generation reproducibility (milestone 2B)

The generator consumes the **active** set through explicit generation policy (initially: ≥ 2 active techniques, trusted only). Each generated version records:

```
content_generations
  id, threat_id, content_id, content_version_id, generation_number,
  policy_version, technique_set_hash, evidence_snapshot_hash,
  evidence_snapshot jsonb, generated_at
```

`technique_set_hash` = sha256 of the sorted effective technique ids; `evidence_snapshot_hash` = sha256 of the canonical JSON of the supporting claim ids, their trust version ids, and normalized confidences. "Why did generation 7 include T1059 when generation 6 did not?" is answerable from the two snapshots. This supersedes Phase 1's `content_version_sources` as the generation-provenance record for intel content; Phase 1 rows remain readable.

## 9. Content ↔ Threat relationships (milestone 2C, `generated_for` in 2A)

### 9.1 Table

```
content_version_threats            -- append-only, version-scoped
  content_version_id FK, threat_id FK,
  relationship_kind ('generated_for'|'emulates'),
  provenance_type ('generator'|'vendor_signed_metadata'|'admin'),
  provenance_ref,                  -- generation_id | version id + signature sha256 | audit_event_id
  created_at,
  PRIMARY KEY (content_version_id, threat_id, relationship_kind)
```

- **generated_for:** written automatically by the generator; exactly one per intel content id (§4.3).
- **emulates:** the content intentionally emulates the threat; created only from signed structured vendor metadata or an audited admin action.
- **Technique overlap** is computed, never stored, and is never attribution.
- **No inheritance.** A new version has only the links it declares; it may deliberately drop one.

### 9.2 Vendor metadata

Builtin YAML gains a structured, signature-covered field:

```yaml
metadata:
  emulates:
    - subject_type: actor
      external_id: G0016
```

`name` and `description` are never parsed for attribution. At intake of a VENDOR_SIGNED version, each `external_id` resolves through the canonical actor registry (`canonical_group_id`) to `threat_id`. Unresolvable → no link; a resolution candidate is created. Adding this metadata changes builtin bytes, so the affected `.sig` files are re-signed and the `verify-all` gate must pass.

### 9.3 Custom content

`POST /api/content/{contentId}/versions/{n}/threats` with `{"threatId":...,"reason":...}` — admin-only, audited, creates `emulates` with `provenance_type='admin'`. No fuzzy or name inference.

## 10. TCV (milestone 2C)

### 10.1 Definition

TCV measures **time to first executable validated coverage**. Clock starts are immutable historical events; clock stops are the first point at which a qualifying content version is executable. Creation, generation, or draft availability never stop a clock.

### 10.2 Clocks (immutable once written)

```
threat_clock_starts
  threat_id, clock ('threat'|'intelligence'), started_at, source_ref,
  PRIMARY KEY (threat_id, clock)
```

- **Threat clock:** earliest `observed_at` of a claim or observation observed under a trusted trust version.
- **Intelligence clock:** first `source_syncs.completed_at` of a sync that produced a trusted claim or observation for the threat.
- Written once (`INSERT … ON CONFLICT DO NOTHING`); never reset by retraction or trust change.

### 10.3 Stops

```
threat_coverage_firsts
  threat_id, relationship_kind ('emulates'|'generated_for'),
  content_version_id, first_executable_at,
  PRIMARY KEY (threat_id, relationship_kind)
```

Written once, at the moment a version linked to the threat by that kind first satisfies the execution gate — `max(link created_at, became-executable time)`. The transitions that make a version executable are: intake of VENDOR+VENDOR_SIGNED+PUBLISHED, transition to LOCAL+LOCAL_TRUSTED+PUBLISHED_LOCAL (`RegisterLocalApproved`, `approveExisting`, `Transition`), and `AttachVendorSignature`; plus link creation for an already-executable version. It is recorded from `content_version_events` / link writes in the same transaction, **not** from a periodic gate scan. The dev-only combination never writes a stop. Later revocation does not move it.

### 10.4 Metrics

Four metrics, never collapsed: **Threat→Emulation, Threat→Generation, Intelligence→Emulation, Intelligence→Generation**.

- `executable_at < clock_start` → `tcv_seconds = 0`, `coverage_state = 'pre_existing'` (never negative).
- No qualifying content → `status = 'open'`, `elapsed = now − start`; only the displayed elapsed value moves.
- Technique overlap produces no TCV.
- Exposed read-only at `GET /api/intel/threats/{id}/tcv` and in the threat list.

## 11. Milestones

| Milestone | Contents | Unblocks |
|---|---|---|
| **2A Identity + content id** | §3 (actor id migration, threats, resolver, unresolved API, campaign/malware/tool actor relations), §4, `generated_for` (§9.1) | Deploying Phase 1 + 2A together |
| **2B Evidence + projection** | §5–§8; all four adapters report completeness; filter moved downstream | Trusted start events |
| **2C Emulation + TCV** | §9.2–9.3, §10; builtin `emulates` metadata + re-sign | TCV reporting |

## 12. Schema delivery and permissions

New tables follow whichever mechanism is on main when the milestone is implemented: Phase 1's boot-time `Ensure…Schema` pattern, or H1's versioned migrations if H1 has merged (then each milestone ships as a numbered migration). `bas_app` grants are declarative and least-privilege:

- append-only tables (`source_trust_versions`, `source_syncs`, `source_observations`, `threat_sources`, `technique_claims`, `content_version_threats`, `content_generations`, `threat_clock_starts`, `threat_coverage_firsts`): `SELECT, INSERT` only — no `UPDATE`, no `DELETE`.
- `threat_techniques`: `SELECT, INSERT, UPDATE`; no `DELETE`.
- `actor_resolution_candidates`: `UPDATE` only on `(status, decided_by, decided_at, decision_reason)`; a CHECK prevents leaving a terminal status via a `decided_at IS NULL ⇔ status = 'unresolved'` constraint plus app enforcement.
- `threats`, `threat_actor_profiles`: no `DELETE`.

Grants are verified in a live boot as `bas_app` (the testcontainers suite runs as superuser and cannot catch lost REVOKEs).

## 13. Acceptance tests

**2A**
1. Actor rename → same actor id, same Threat.
2. New alias → same actor when the resolver has sufficient evidence.
3. Ambiguous alias → unresolved, no merge.
4. Same actor from MISP + OpenCTI + OTX → one Actor Threat.
5. New actor → new actor id + new Threat.
6. Existing campaign referencing a renamed actor → relationship survives.
7. Existing campaign/malware/tool deduplication → behavior unchanged.
8. MITRE G-ID absent → actor still gets a valid Audspect id.
9. MITRE G-ID changes → Audspect id unchanged.
10. Content id: same threat id → same content id (golden vector checked in); changing the threat's display name never changes it.
11. Hash collision with a different threat → generation fails closed, no write to the other threat's content.
12. Unresolved candidate → no Threat, no content; `link` / `new` / `dismiss` each terminal; a second decision is refused; `dismiss` creates nothing.
13. Name-derived legacy content with approvals or runs → untouched, listed in the inventory.

**2B**
14. Partial MISP sync (one event detail fails) → additions recorded, zero retractions.
15. OpenCTI result at exactly the `first:` limit → `truncated`, zero retractions.
16. OTX page cap or later-page error → never authoritative, zero retractions.
17. Complete snapshot without a previously claimed technique → one retraction row; projection retracted with `source_retraction`; `first_seen_at` unchanged.
18. Two-source example (A drops, B remains → active, first_seen Jan; B drops → retracted, first_seen Jan).
19. Actor going from 2 MISP techniques to 1 → the remaining claim stays active evidence; generation policy excludes it.
20. Confidence 42 from a trusted source → active, `best_confidence = 42`.
21. Untrusted-then-trusted OTX example → first trusted attribution is the first claim observed under trust.
22. Trust revocation → `trust_revocation` reason, distinguishable from source retraction.
23. Adapter that requests a retraction on a non-authoritative sync → refused by the evidence layer.
24. Generation snapshots explain a technique-set difference between two generations.

**2C**
25. Builtin with `emulates: G0016` → link after signature verification; free-text name never used.
26. Unresolvable G-ID → no link, candidate created.
27. New version without `emulates` → no link (no inheritance).
28. DRAFT never stops a clock; first executable version does; later revocation does not move it.
29. Pre-existing coverage → `tcv_seconds = 0`, `coverage_state = pre_existing`.
30. No coverage → open with elapsed time; start frozen.
31. Retraction then reappearance → no clock restart.
32. Dev-only executable combination → no stop recorded.
33. Admin `emulates` link on an already-executable custom version → stop at link time.

## 14. Rulings carried from Phase 1 that still apply

ERROR, NO_DATA and NOT_APPLICABLE are excluded from detection denominators; dev builds deny VENDOR_SIGNED; system-only lifecycle moves refuse human actors; never inflate a score; no "competes with Picus/SafeBreach/Cymulate/AttackIQ" claims until the factory produces measured numbers.
