# Network BAS Mastery Phase 7C: India/UAE Regulatory and Assurance Mapping — Design Spec

## 1. Goal

Add the third and final of Phase 7's sector-specific sub-projects (7A OT/ICS safety gating and 7B healthcare network-isolation validation are both done, reviewed, and fixed): a versioned regulatory-obligation-mapping layer for India and UAE, per the master spec (`docs/superpowers/specs/2026-10-13-network-bas-architecture-design.md`, Phase 7 section) and `network.txt` §3.

`network.txt` §3 requires: mapping each applicable obligation (RBI/SEBI/CERT-In for India; UAE Central Bank and relevant UAE cybersecurity requirements for UAE) to relevant network controls, simulations, evidence, and remediation workflows; maintaining source references, effective dates, applicability conditions, and version history; distinguishing mandatory obligations from guidance/contractual/recommended ones; configurability by jurisdiction, sector, entity type, and customer; and producing traceable evidence for authorised audits — while never presenting a successful simulation or report as proof of regulatory compliance without qualified review (`network.txt` §3/§9, non-negotiable).

This phase's exit bar, matching the master spec's own definition of done, is deliberately narrow: at least one regulatory obligation per jurisdiction mapped end-to-end from obligation → control → evidence, with version/source traceability. The data model carries the generality (jurisdiction/sector/entity-type/source/version/effective-date fields, usable for any future obligation); only two concrete obligations are seeded in this increment.

## 2. Relationship to Existing Code — What's Reused, What's Not

- **A separate, pre-existing `internal/compliance` package already ships general Audspect compliance scoring** (frameworks `RBI_CSF`, `SEBI_CSCRF`, `CERT_IN`, `IRDAI_CSF`, `ISO_27001_2022`, `NIST_CSF_2`, `PCI_DSS_V4`, a `GetComplianceReport` endpoint, CSV/HTML/PDF export, `compliance_snapshots` persistence). It predates this initiative and maps MITRE ATT&CK technique IDs to framework controls, scored from scenario-run `TechniqueEvidence` — squarely the **identity domain**. It has zero UAE frameworks, zero link to Network BAS's own network evidence, and zero obligation-level metadata (source reference, effective date, applicability conditions, jurisdiction/sector/entity-type). **This phase does not import, extend, or depend on `internal/compliance` in any way** — doing so would cross this initiative's own non-negotiable rule that the identity domain, the network-connectivity domain, and the control-efficacy domain never cross-couple at the data layer (correlation is reporting-layer only). `internal/compliance`'s `FrameworkMeta`/`ControlDef`/YAML-loader shape is noted here only as a structural precedent that this phase's own package deliberately does **not** reuse, since obligations need richer per-record metadata than framework-level controls do.
- **No new composition/scoring engine.** Per the master spec's own words for Phase 7: "Does not introduce a second scoring or reporting system." This phase's new package never calls into `networkpolicy`, `networkpath`, `zoneisolation`, `remoteaccess`, or any other Phase 1–6B evidence-producing capability itself. It consumes their *output* only as data an operator has already obtained and explicitly submits for recording — it imports none of their Go types, so it has **zero** Go import dependency on any Phase 1–6B package, a stronger boundary than merely avoiding identity/control-efficacy imports.
- **No customer-targeting mechanism.** Audspect is on-prem, one deployment per customer (no multi-tenant/SaaS model). `Jurisdiction`/`Sector`/`EntityType` are descriptive, filterable fields on each obligation record; "configurable... by customer" is satisfied by the catalog itself being editable per-deployment data (like every other Phase 7 import), not a targeting system.

## 3. Package: `internal/regobligation`

### 3.1 Obligation Catalog

```go
package regobligation

import "time"

type ObligationType string

const (
	ObligationMandatory   ObligationType = "mandatory"
	ObligationGuidance    ObligationType = "guidance"
	ObligationContractual ObligationType = "contractual"
	ObligationRecommended ObligationType = "recommended"
)

const MaxControlMappingsPerObligation = 50

// ControlMapping names what Network BAS capability would evidence this
// obligation. CapabilityName is a plain string tag (e.g.
// "zoneisolation.isolation-check") -- never an imported type, since this
// package has no Go dependency on any Phase 1-6B package.
type ControlMapping struct {
	CanonicalID    string `json:"canonicalId"`
	ControlName    string `json:"controlName"`
	CapabilityName string `json:"capabilityName"`
	Note           string `json:"note,omitempty"`
}

// Obligation is one regulatory requirement -- catalog metadata, individually
// CRUD'd and versioned (never bundled into a batch "import" the way
// otsafety/zoneisolation imports are, since obligations evolve
// independently of each other, not as one coherent topology-like snapshot).
type Obligation struct {
	ID              string           `json:"id,omitempty"`
	Jurisdiction    string           `json:"jurisdiction"`
	Regulator       string           `json:"regulator"`
	Sector          string           `json:"sector,omitempty"`
	EntityType      string           `json:"entityType,omitempty"`
	Title           string           `json:"title"`
	Description     string           `json:"description,omitempty"`
	ObligationType  ObligationType   `json:"obligationType"`
	SourceReference string           `json:"sourceReference"`
	EffectiveDate   time.Time        `json:"effectiveDate"`
	Version         string           `json:"version"`
	ControlMappings []ControlMapping `json:"controlMappings"`
	CreatedBy       string           `json:"createdBy,omitempty"`
	CreatedAt       time.Time        `json:"createdAt,omitempty"`
}
```

**Validation** (`validateObligation`, in the `internal/api` handler layer, mirroring `otsafety.validateOTSafetyImport`'s discipline): `Jurisdiction`, `Regulator`, `Title`, `SourceReference` non-empty; `EffectiveDate` non-zero; `Version` non-empty; `ObligationType` must be one of the four declared constants (rejecting empty string or any typo); `ControlMappings` non-empty (at least one), capped at `MaxControlMappingsPerObligation`; each `ControlMapping` requires non-empty `ControlName` and `CapabilityName`. `ID` and `CreatedAt` are server-assigned.

### 3.2 Evidence Snapshot

```go
type SnapshotStatus string

const (
	SnapshotCaptured   SnapshotStatus = "captured"
	SnapshotIncomplete SnapshotStatus = "incomplete"
)

const CurrentSnapshotSchemaVersion = "1"

// EvidenceSnapshot is an immutable, point-in-time capture of a Network BAS
// check's output, submitted by an operator who already ran that check
// themselves. It is explicitly NOT a persisted execution run of the check
// itself -- isolation-checks, remote-access-path checks, network-path
// checks, and cloud-path checks are all deliberately ephemeral (computed
// fresh, never persisted, confirmed by reading their handlers' own doc
// comments) -- this snapshot exists so this phase has something durable
// and auditable to point at, without changing that deliberate behavior or
// building persistence into any existing Network BAS capability, and
// without this package calling into any of them itself.
//
// Labeled a captured assessment, never implying the underlying check was
// independently rerun or that the snapshot proves the CURRENT state of
// anything -- only the state at CapturedAt.
type EvidenceSnapshot struct {
	ID                   string            `json:"id,omitempty"`
	SchemaVersion        string            `json:"schemaVersion,omitempty"`
	ObligationID         string            `json:"obligationId"`
	ControlMappingID     string            `json:"controlMappingId"`
	ObligationVersion    string            `json:"obligationVersion,omitempty"`
	CapabilityName       string            `json:"capabilityName"`
	ImportReferences     map[string]string `json:"importReferences,omitempty"`
	QueryParameters      map[string]any    `json:"queryParameters,omitempty"`
	CapturedOutcome      string            `json:"capturedOutcome,omitempty"`
	CapturedConfidence   string            `json:"capturedConfidence,omitempty"`
	CapturedLimitations  string            `json:"capturedLimitations,omitempty"`
	Status               SnapshotStatus    `json:"status"`
	IncompleteReason     string            `json:"incompleteReason,omitempty"`
	CapturedBy           string            `json:"capturedBy,omitempty"`
	CapturedAt           time.Time         `json:"capturedAt,omitempty"`
	Note                 string            `json:"note,omitempty"`
}
```

**Validation** (`validateEvidenceSnapshot`, in the handler layer, requires a DB lookup so it is not a pure function): `ObligationID` must resolve to a real persisted `Obligation` (404 if not); `ControlMappingID` must match one of that obligation's own `ControlMapping.CanonicalID` values (a lookup against the obligation's own data, not a format check — 400 if no match); `CapabilityName` must equal the matched `ControlMapping.CapabilityName` (a consistency guard against copy-paste mismatches); `Status` must be `captured` or `incomplete`; if `captured`, `CapturedOutcome` must be non-empty; if `incomplete`, `IncompleteReason` must be non-empty — one or the other is mandatory, so a submission that can't produce a real outcome must say so rather than defaulting to something that reads as fine.

**Server-assigned fields** (never trusted from the request body, so a caller cannot spoof the audit trail): `ID`, `SchemaVersion` (= `CurrentSnapshotSchemaVersion`), `ObligationVersion` (copied from the looked-up `Obligation.Version` at creation time), `CapturedAt` (= server's current time).

### 3.3 No Compliance Verdict, Anywhere

Neither type carries, computes, or displays a "compliant: yes/no" field. A reader (or auditor) inspects an obligation's control mappings and the chronological list of its evidence snapshots and judges compliance themselves. This is the mechanism — not a disclaimer string repeated on every response — by which this phase satisfies the non-negotiable constraint that a successful check is never presented as proof of regulatory compliance without qualified review.

## 4. Persistence & API

Two new tables: `regulatory_obligations`, `regulatory_evidence_snapshots` (both jsonb-payload, same marshal-struct pattern as `otsafety_store.go`/`zoneisolation_store.go`; `regulatory_evidence_snapshots` additionally indexed/queryable by `obligation_id`). Store functions mirror the established pattern exactly: `EnsureRegulatoryObligationSchema`/`InsertRegulatoryObligation`/`scanRegulatoryObligation`/`GetRegulatoryObligation`/`ListRegulatoryObligations`, and `EnsureEvidenceSnapshotSchema`/`InsertEvidenceSnapshot`/`scanEvidenceSnapshot`/`GetEvidenceSnapshot`/`ListEvidenceSnapshotsByObligation(ctx, db, obligationID)`.

New permission `CanManageRegulatoryObligations Permission = "regulatory-obligation:manage"` (granted to `RoleAdmin` and `RoleAnalyst`, same placement pattern as `CanImportOTSafetyConfig`/`CanImportZoneIsolationConfig`), gating both GET and POST on both resources (matching the established pattern where every Phase 7 import's own permission gates its own GET and POST alike):

- `POST /api/regulatory-obligations` — create one obligation.
- `GET /api/regulatory-obligations` — list, newest-first (matching every existing `List*` convention in this codebase).
- `GET /api/regulatory-obligations/{id}` — get one.
- `POST /api/regulatory-evidence-snapshots` — create one snapshot (the request body is the obligation/control-mapping reference plus the already-obtained check output and its provenance; the handler performs the lookups and consistency checks in §3.2 and persists — it calls no other package's composition logic).
- `GET /api/regulatory-evidence-snapshots?obligationId={id}` — list all snapshots for one obligation, newest-first.
- `GET /api/regulatory-evidence-snapshots/{id}` — get one.

## 5. Concrete Seed Obligations

Not hardcoded migration data — created through the normal CRUD API and proven via integration tests, the same way every other Phase 7 capability's acceptance criteria are demonstrated with realistic example data rather than a special seed path.

**India — RBI network-segmentation requirement:**
```json
{
  "jurisdiction": "India",
  "regulator": "RBI",
  "sector": "Banking",
  "entityType": "Regulated Financial Institution",
  "title": "Network segmentation for critical payment/banking systems",
  "obligationType": "mandatory",
  "sourceReference": "RBI Cyber Security Framework for Banks",
  "effectiveDate": "2016-06-02T00:00:00Z",
  "version": "RBI CSF 2016 (as amended)",
  "controlMappings": [
    {
      "canonicalId": "cm-1",
      "controlName": "Segmentation between critical payment-processing zones and the general corporate network",
      "capabilityName": "zoneisolation.isolation-check"
    }
  ]
}
```

**UAE — UAE Central Bank vendor remote-access control requirement:**
```json
{
  "jurisdiction": "UAE",
  "regulator": "UAE Central Bank",
  "sector": "Banking",
  "entityType": "Regulated Financial Institution",
  "title": "Third-party/vendor remote-access control for regulated financial institutions",
  "obligationType": "mandatory",
  "sourceReference": "UAE Central Bank Information Assurance Standards",
  "effectiveDate": "2018-01-01T00:00:00Z",
  "version": "IAS 1.0",
  "controlMappings": [
    {
      "canonicalId": "cm-1",
      "controlName": "Vendor VPN/remote-access paths are routed only through approved, monitored channels",
      "capabilityName": "remoteaccess.path-check"
    }
  ]
}
```

Each is proven end-to-end by: creating the obligation, then submitting an `EvidenceSnapshot` against its `cm-1` control mapping with `Status: "captured"`, a realistic `CapturedOutcome` (e.g. `"no-violation-found"` for the India example, `"confirmed-violation"` for the UAE example — picked to also prove the model reports an adverse outcome, not only a clean one), the corresponding capability's real import-reference field names in `ImportReferences` (e.g. `{"topologyImportId": "...", "isolationImportId": "...", "policyImportId": "..."}` for the India example), and verifying the persisted snapshot round-trips with server-assigned `ObligationVersion`/`CapturedAt`.

## 6. Review Focus

1. A snapshot submitted with `Status: "incomplete"` and a non-empty `IncompleteReason` must never be silently dropped or indistinguishable from a captured one when an obligation's snapshots are listed — a reasonable reader must see it distinctly flagged.
2. A `ControlMappingID` that doesn't match any of the referenced obligation's own declared `ControlMapping.CanonicalID` values must be rejected (400), not silently accepted as a dangling reference.
3. `ObligationVersion` and `CapturedAt` on a persisted snapshot must reflect server-assigned values captured at creation time — a test must prove a caller-supplied value for either field in the request body is ignored/overwritten, not merely that the fields end up present.
4. The two concrete seed obligations (India/RBI, UAE/UAE-CB) must each be independently creatable, each independently support attaching an evidence snapshot, and listing all obligations must return both without either corrupting or leaking into the other's control-mapping/snapshot data.
5. An `Obligation` with `ObligationType` outside the four declared constants (empty string, or a typo) must be rejected at creation (400) — the mandatory/guidance/contractual/recommended distinction network.txt explicitly requires must be enforced, not merely documented.

## 7. Safety Constraints

Carried forward from `network.txt` §3/§9, unchanged: a successful check or generated report is never presented as proof of regulatory compliance without qualified review — enforced structurally (§3.3), not by a disclaimer field. Regulatory mapping must be reviewed against current official sources and qualified compliance guidance; `SourceReference`/`EffectiveDate`/`Version` give this phase's machinery for tracking that review, but keeping citations current against the real regulator's published text remains the user's own responsibility, not something this phase validates.

## 8. Explicitly Deferred

- PDF/CSV export of obligation/evidence data — pure presentation work on top of already-structured JSON; GET responses already satisfy "traceable evidence for audits."
- Broader obligation catalog beyond the two seed examples (additional RBI/SEBI/CERT-In/UAE-CB obligations) — pure data-entry against an already-proven model.
- Non-mandatory (guidance/contractual/recommended) example obligations — the enum supports them; no seed data exercises them yet.
- Live evidence re-querying or automatic re-capture — rejected, not merely deferred, per the locked Option B decision: this package will never call into `zoneisolation`/`remoteaccess`/`networkpolicy`/or any other Phase 1–6B capability itself.
- Any customer/tenant-targeting mechanism — rejected per this initiative's locked on-prem, one-deployment-per-customer architecture.

## 9. Acceptance Criteria

Matching the master spec's own exit criterion: at least one regulatory obligation per jurisdiction (India, UAE) is mapped end-to-end from obligation → control → evidence, with version/source traceability — satisfied by the two seed obligations in §5, each with a real validated `Obligation` record naming a real Network BAS capability, and a real `EvidenceSnapshot` (`Status: "captured"`) recorded against that mapping, proven via a dedicated integration test per jurisdiction.
