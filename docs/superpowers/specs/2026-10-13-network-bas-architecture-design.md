# Network BAS Mastery: Architecture Specification

## Executive Summary

Audspect's Network BAS Mastery initiative extends Audspect from host/identity-centric breach-and-attack simulation into network-layer validation: what is reachable, which policies are actually enforced, which attack paths cross network boundaries, and whether deployed network security controls prevent, detect, and contain controlled test traffic.

This specification is a **repository-verified gap analysis plus a seven-phase roadmap**, scoped at the architecture level. It establishes what already exists and must not be rebuilt, what is new, how the new work is structured, and the order of delivery. It deliberately does **not** contain file-by-file designs, interface signatures, or task breakdowns — each phase gets its own implementation specification, written when that phase begins, following this document's architecture.

Source requirements document: `network.txt` (repo root). That document is a capability vision; this specification reconciles it against what Audspect's codebase actually contains today.

## 1. Repository-Verified Gap Analysis

Every classification below was checked directly against the current repository, not inferred from `network.txt`'s own description of what Audspect "should" do.

| network.txt domain | Status | Evidence |
|---|---|---|
| 1.1 Discovery & exposure validation | **Missing** | `internal/exposure/` reports CVE/criticality exposure for known, agent-managed hosts only (`AssetIdentity{HostKey, AgentID, Managed}`) — it does not discover unmanaged devices or compare inventory to discovered reality. T1046 (Network Service Discovery) exists only as a vendor ART atomic (literal `nmap`/`Test-NetConnection` commands dispatched as-is, `internal/scenario/resource.go:199`) — no discovery engine, no inventory comparison. |
| 1.2 Firewall & segmentation validation | **Partial** | `internal/attackpath` detects cross-segment edges (`analytics.go:265`, `SegmentationViolations()`), but `Segment` is a manually operator-tagged string (`assets.go:14,58-59`) — not derived from real firewall/ACL/VLAN configuration — and reachability edges are limited to 3 AD-lateral-movement ports (SMB/WinRM/RDP). Host-based firewall-enabled/disabled checks exist (`scenarios/windows-security-config.yaml`, `scenarios/ubuntu-hardening-validation.yaml`) but are single-host posture checks, not source-to-destination test matrices. |
| 1.3 Attack paths & lateral movement | **Existing (identity-scoped)** | `internal/attackpath` is a real directed multigraph (Node/Edge/Graph) merging AD graph data (SharpHound) with agent-collected SMB/WinRM/RDP reachability, with scoring and blast-radius analysis. `internal/latmove` independently validates 7 lateral-movement techniques, lab-independent. Both are real and well-tested, but scoped entirely to Windows/AD identity reachability — not general L3/L4 paths across arbitrary zones, routers, or firewalls. |
| 1.4 Control efficacy (FW/IDS/IPS/NDR/EDR/NAC/SIEM/SWG/SASE/SSE/VPN) | **Partial (EDR/SIEM only)** | Real connectors exist for EDR (`internal/vendors/{crowdstrike,defender}`, `internal/detectverify/{crowdstrike,defenderxdr}.go`) and SIEM (`internal/detectverify/elastic.go`, `internal/siem/qradar.go`), unified behind `detectverify.Connector` (`Verify`, `TestConnection`) with a provider switch (`connector.go:100-115`). Zero firewall/IDS/IPS/NDR/NAC/SWG/SASE/SSE/VPN vendor integrations exist. Only the integration *pattern* is reusable. |
| 1.5 Remote access & trust boundaries | **Missing** | No VPN, bastion/jump-host, or zero-trust access-policy testing code found anywhere in `internal/`. |
| 1.6 DNS, protocols, infrastructure security | **Partial (wrong angle)** | `scenarios/dlp-exfiltration-dns-tunnel.yaml` + `internal/dnssink/` validate whether DNS-tunneled *data exfiltration* is blocked/detected — not DNS security itself. No cache-poisoning, zone-transfer, DNSSEC, resolution-hijacking, weak-TLS, or cert-validation testing exists. |
| 1.7 Cloud & hybrid network security | **Missing (wrong graph shape)** | `internal/cloudgraph` models IAM authorization paths (identity → permission → resource) — a materially different edge semantic from VPC/security-group/route-table/peering connectivity. No network-topology modeling for cloud environments exists. |
| 1.8 Controlled data-movement | **Existing and verified** | 9 DLP exfiltration channel scenarios (`scenarios/dlp-exfiltration-{cloud-storage,coderepo,dns-tunnel,multichannel,sftp,sink-https,smtp,telnet,webhook}.yaml`) plus `dlp-exfiltration-validation.yaml`, each paired with a real sink package (`cloudsink`/`dnssink`/`sftpsink`/`smtpsink`/`telnetsink`/`webhooksink`). This is the strongest existing precedent in the repository and already matches this domain's full shape: synthetic data, authorized destinations, protocol/destination/result recording, DLP/SIEM correlation. |
| 1.9 Detection, response, containment | **Partial (endpoint/identity-scoped)** | `internal/detecteffectiveness`, `internal/detectverify` (EDR/SIEM alert correlation + latency), `internal/controlhealth`, `internal/rwdetect` (ransomware-specific) are all real but endpoint/identity/ransomware-scoped. The connector/correlator *pattern* is reusable; no network-security-product detection/containment correlation exists. |
| 1.10 Resilience & availability | **Missing** | No failover/redundancy/availability-testing code found anywhere in `internal/`. |

**Graph/path-modeling precedent assessment:** three existing graph-like structures were checked for reuse — `attackpath` (real Node/Edge multigraph, but edges are tightly coupled to AD identity concepts: SID-based host reconciliation, ACL-abuse edges, SharpHound-specific fields), `cloudgraph` (real six-state `PathState` enum, but edges model IAM authorization, not L3/L4 connectivity), and `admatrix`/`adchain` (capability-based BFS/search, not an explicit graph at all). None fit network semantics — stateful L3/L4 5-tuples, routing-table hops, VLAN/subnet membership as first-class structure are absent from all three. **Decision: build a new, parallel `internal/networkgraph` package** — the same architectural move Cloud BAS made relative to `admatrix`/`adchain` — while reusing `cloudgraph.PathState` and `cloudgraph.Provenance` verbatim by direct import (not redefinition), since both types are already provider-agnostic in shape and `network.txt`'s own language ("theoretical/inferred/confirmed-reachable/demonstrated-control-failure") maps onto `PathState`'s six values near 1:1. This creates the one deliberate cross-package dependency in this architecture: `internal/networkgraph` → `internal/cloudgraph` (for these two types only, nothing else).

**Orchestration seam confirmed:** both AD Mastery and Cloud BAS scenarios dispatch through `internal/scenario.Engine` via YAML scenario files (`scenario.NewEngine(dir)`, `engine.go:55`). Network BAS follows the same seam rather than building a parallel execution framework, per `network.txt` §10's own requirement.

## 2. Three-Evidence-Domain Architecture

Network BAS introduces network-connectivity evidence alongside Audspect's existing identity evidence and control-efficacy evidence. These three domains are kept **independently typed, independently evaluated, and never merged into one path-truth model.**

- **Identity domain** (existing — `internal/attackpath`, `internal/admatrix`, `internal/adchain`, `internal/latmove`) — AD/host identity reachability. **Untouched by this initiative.**
- **Network-connectivity domain** (new — `internal/networkgraph`) — L3/L4 reachability across assets, zones, routes, and firewall rules. Path confidence is expressed using `cloudgraph.PathState`'s six existing values verbatim — `candidate`, `conditionally_reachable`, `policy_supported`, `observed`, `blocked`, `unknown` — with their existing semantics unchanged. `policy_supported` (a policy permits the path) is never treated as equivalent to `observed` (the path was actually exercised), and neither is treated as proof that a security control is effective.
- **Control-efficacy domain** (existing, extended — `internal/detectverify`) — whether a security product actually prevented, detected, or contained a given controlled test. Extended through its existing `Connector` interface and provider-switch pattern (Phase 4) without forcing network-specific semantics into unrelated (EDR/SIEM) providers.

**Correlation is a reporting-layer join, not a graph merge.** A combined finding cites specific evidence records from each domain by stable reference (asset ID, account ID, identity ID, test-run ID, timestamp), including each record's own provenance and limitations. An identity-domain edge is never treated as proof of network reachability; an open network-connectivity path is never treated as proof that an identity-based attack succeeds. Evidence missing from one domain is recorded as `unknown` in that domain — never inferred from another domain's evidence.

```
   Identity evidence          Network-connectivity evidence       Control-efficacy evidence
   (attackpath/admatrix/       (networkgraph — new, reuses         (detectverify — extended,
    adchain/latmove —           cloudgraph.PathState +              new FW/IDS/IPS/NDR/NAC
    untouched)                  cloudgraph.Provenance)              providers)
          |                            |                                   |
          +----------------------------+-----------------------------------+
                                        |
                               Reporting layer
                      (joins by asset/account/identity/
                       test-run/time reference; cites each
                       domain's evidence + provenance + limitations
                       explicitly; never infers across domains)
```

## 3. Reuse Boundaries & No-Rebuild List

These are locked for the entire initiative, not just Phase 1:

- `internal/attackpath`, `internal/admatrix`, `internal/adchain`, `internal/latmove` — identity-path layer, kept intact as a separate layer the reporting layer can later correlate against. No phase of this initiative modifies these packages' core logic.
- The 9 DLP exfiltration channel scenarios (`scenarios/dlp-exfiltration-{cloud-storage,coderepo,dns-tunnel,multichannel,sftp,sink-https,smtp,telnet,webhook}.yaml`) and `dlp-exfiltration-validation.yaml`, plus their sink packages (`cloudsink`, `dnssink`, `sftpsink`, `smtpsink`, `telnetsink`, `webhooksink`) — the reference implementation for controlled data-movement testing (§1.8). Kept as-is; Network BAS does not rebuild egress/data-movement testing.
- `internal/detectverify.Connector` and its provider-switch pattern — extended with new provider cases in Phase 4, never restructured to special-case network semantics inside existing EDR/SIEM provider code.
- `cloudgraph.PathState` and `cloudgraph.Provenance` — imported by `internal/networkgraph`, not copied or redefined.
- `internal/scenario.Engine` — the single dispatch seam for every new network scenario YAML file, matching AD Mastery and Cloud BAS precedent.

## 4. Seven-Phase Roadmap

### Phase 1 — Network Discovery & Evidence Foundation

**Current state:** Missing (§1.1 above). No existing package models network assets, zones, testing vantage points, or network-specific evidence/provenance.

**Reuse / no-rebuild:** Imports `cloudgraph.PathState` and `cloudgraph.Provenance` directly. Does not touch `internal/exposure`, `internal/attackpath`, or any identity package.

**Architecture changes & dependencies:** New `internal/networkgraph` package. Core types: network asset, network zone, testing vantage point (internal/external/branch/datacenter/cloud/hybrid, per `network.txt` §1.1), network observation, network finding, network evidence record — each carrying `cloudgraph.Provenance`-shaped source/observed-at/confidence/limitation fields. Establishes scope enforcement (every test tied to an authorized target scope) and safety classification fields on the test/finding types, mirroring `network.txt` §9's non-negotiable rules at the type level. On top of this foundation, this phase also delivers the first real capability: authorized asset discovery and service-reachability observation from a declared testing vantage point, dispatched via `scenario.Engine`, producing `networkgraph` observations with full provenance — this is the "asset inventory... observed reachability" half of the phase, not deferred. It does not yet compare discovered assets against an approved inventory (that requires an inventory-import mechanism, deferred to this phase's own implementation specification) and does not yet build multi-hop paths (Phase 3) or firewall-policy test matrices (Phase 2).

**Acceptance criteria & test strategy:** Every test type is associated with an authorized scope field that cannot be empty. Every finding type has a mandatory evidence-reference field. `Unknown` and other non-terminal `PathState` values are representable and are not collapsible into a false positive/negative by any helper function. A discovery run from a declared vantage point produces asset/service observations with full provenance, restricted to the authorized scope. Unit tests cover type construction, scope-enforcement rejection paths, and provenance round-tripping; at least one lab-backed integration test exercises a real discovery run end-to-end (authorized scope in, observed assets/services with provenance out).

**Safety constraints & evidence requirements:** Discovery runs are rate-limited, scope-enforced, and non-disruptive (service/reachability checks only — no exploitation, no credential interception). Evidence model must make it structurally impossible to omit provenance (source, observed-at, confidence) on a finding.

**Definition of done & exit criteria:** `internal/networkgraph` compiles, is tested, and exposes both the typed foundation (assets/zones/vantage-points/observations/findings/evidence) and a working, scope-enforced discovery capability that produces evidence-backed observations from a declared vantage point. Phase 2 builds firewall/segmentation test matrices on top of these observations; Phase 3 builds multi-hop paths on top of them.

### Phase 2 — Real Firewall & Segmentation Validation

**Current state:** Partial (§1.2 above) — only a manually-tagged `Segment` string and same-segment-skip check in `attackpath`, no real policy-derived test matrices.

**Reuse / no-rebuild:** Does not modify `attackpath.Segment` or `SegmentationViolations()` — those remain the identity-domain's own segmentation signal. Builds new, independent segmentation-testing logic on Phase 1's `networkgraph` types.

**Architecture changes & dependencies:** Depends on Phase 1. Adds firewall-rule and zone-boundary types to `networkgraph`, plus source-to-destination test-matrix generation and execution against authorized vantage points, dispatched via `scenario.Engine`. Introduces the first new scenario YAML files (firewall/segmentation positive and negative connectivity tests).

**Acceptance criteria & test strategy:** Permitted and prohibited flows are both tested (positive and negative cases). Observed results are compared against the declared/expected policy and recorded with a `PathState` value, not a boolean. Confirmed violations carry reproducible evidence (source, destination, port, protocol, timestamp, observed result). Tests include: a permitted-flow case recorded as `observed`, a prohibited-flow case blocked and recorded as `blocked`, and an undeclared-policy case recorded as `unknown` (never inferred as either).

**Safety constraints & evidence requirements:** Tests restricted to authorized target scope and rate-limited; no traffic-flooding or disruptive protocol abuse (per `network.txt` §1.6/§9). Every finding cites the specific test run, vantage point, and policy reference it was evaluated against.

**Definition of done & exit criteria:** A source-to-destination test matrix can be generated from declared network policy, executed from an authorized vantage point, and produce evidence-backed `PathState`-classified results, distinguishing declared policy from demonstrated behavior.

### Phase 3 — L3/L4 Attack-Path Engine

**Current state:** Existing only for identity-scoped paths (§1.3); no general network-layer multi-hop engine exists.

**Reuse / no-rebuild:** Does not extend `attackpath`'s Node/Edge types. Treats `attackpath`'s existing SMB/WinRM/RDP reachability and `SegmentationViolations()` output as a **corroborating evidence input** the network-connectivity domain may reference by asset key — never as a foundation the new engine inherits from or mutates.

**Architecture changes & dependencies:** Depends on Phases 1-2. Adds multi-hop path construction to `networkgraph`: candidate path generation across zones/routes/firewall rules built in Phase 2, each hop independently validated and `PathState`-classified, with path-level confidence derived from (not equal to) its weakest hop's confidence.

**Acceptance criteria & test strategy:** Candidate paths carry their generating assumptions and evidence. Each hop is independently verifiable. A path's overall classification never exceeds its weakest hop's classification (e.g., one `unknown` hop prevents the whole path from reading as `observed`). Tests cover: single-hop paths, multi-hop paths where one hop is deliberately `blocked`, and a path referencing an identity-domain SMB edge as corroborating (not authoritative) evidence.

**Safety constraints & evidence requirements:** Path generation prioritizes relevant, testable paths over path count (per `network.txt` §5 Stage 3). A theoretical/candidate path is never presented as a demonstrated attack without the full hop-by-hop evidence chain.

**Definition of done & exit criteria:** The engine distinguishes theoretical, inferred, confirmed-reachable, and demonstrated-control-failure paths using `PathState`, with every classification traceable to per-hop evidence, and can optionally cite (without depending on) identity-domain evidence for AD-adjacent hops.

### Phase 4 — Network Security Control Efficacy

**Current state:** Partial, EDR/SIEM only (§1.4 above). Zero FW/IDS/IPS/NDR/NAC/SWG/SASE/SSE/VPN connectors exist.

**Reuse / no-rebuild:** Extends `detectverify.Connector` and its provider-switch (`connector.go:100-115`) with new provider cases. Does not modify the `Connector` interface itself or any existing EDR/SIEM provider implementation.

**Architecture changes & dependencies:** Depends on Phase 2 (tests need a declared/expected-vs-observed network event to correlate a control response against). Priority order for new providers: firewall and IDS/IPS first, then NDR, then NAC, then SWG/SASE/SSE, then VPN (per your locked priority). Each new provider implements `Verify`/`TestConnection` against that product's real or lab-backed API; synthetic/mock providers are explicitly labeled as such and never conflated with real-provider results in reporting.

**Acceptance criteria & test strategy:** For each new provider, tests confirm: a controlled test is correctly correlated to the right provider event, detection/containment latency is recorded only when timestamps are trustworthy, and a provider with no real backing (synthetic/lab) is distinguishable in output from a verified real integration. No phase ships a real-provider claim backed only by a mock.

**Safety constraints & evidence requirements:** Never claim a real security product was tested when only a mock/synthetic provider was used (per `network.txt` §9, non-negotiable). Missing telemetry is recorded as inconclusive, not as a detection failure, until the telemetry source's operability is independently confirmed.

**Definition of done & exit criteria:** At least one new real-or-lab-backed firewall/IDS-IPS provider is integrated end-to-end (test → product event → correlated finding), with the pattern proven for the remaining provider categories to follow in the same phase or a documented follow-on.

### Phase 5 — DNS, Protocol & Infrastructure Security

**Current state:** Partial, wrong angle (§1.6 above) — only DNS-tunnel exfiltration detection exists, not DNS security itself.

**Reuse / no-rebuild:** Does not modify `internal/dnssink` or the `dlp-exfiltration-dns-tunnel` scenario — those remain the data-movement domain's DNS-channel test, untouched. This phase's DNS work is a distinct network-connectivity-domain capability.

**Architecture changes & dependencies:** Depends on Phase 1 (evidence foundation) and loosely on Phase 2 (vantage-point infrastructure). Adds real DNS-security testing (resolution-behavior checks, applicable trust-weakness checks) and protocol/transport checks (insecure protocol detection, certificate-validation checks where testable) as new `networkgraph`-backed scenario types.

**Acceptance criteria & test strategy:** Each new check type has a documented expected-vs-observed behavior and records `PathState`-equivalent confidence. Encrypted-traffic visibility limitations are recorded explicitly, not silently skipped. Tests cover at least one DNS-resolution-behavior check and one insecure-protocol/weak-transport check end-to-end.

**Safety constraints & evidence requirements:** No credential interception, no disruptive protocol abuse, no uncontrolled traffic generation (per `network.txt` §1.6, explicit). Authorized scope and rate limits enforced identically to Phase 2.

**Definition of done & exit criteria:** At least one real DNS-security check and one protocol/transport-security check execute end-to-end with evidence-backed, scope-limited results, clearly separated from the existing DNS-tunnel exfiltration detection capability.

### Phase 6 — Cloud & Remote-Access Networking

**Current state:** Missing, wrong graph shape for cloud (§1.7); fully missing for remote access (§1.5).

**Reuse / no-rebuild:** Does not modify `internal/cloudgraph`'s IAM-authorization model. Extends the network-connectivity domain (`networkgraph`) with cloud-topology-aware types (routes, security groups, peering, effective connectivity) that reference cloud accounts/resources by the same canonical IDs `cloudgraph` already uses, without inheriting its IAM-path semantics.

**Architecture changes & dependencies:** Depends on Phases 1-3 (the path engine must exist before cloud topology paths can be classified) and on the Cloud BAS initiative's own account/resource identifiers remaining stable (cross-initiative reference, not a code dependency — Cloud BAS is currently held per separate direction, tracked in `cloud.txt`). Adds VPN, partner-connectivity, and remote-access boundary validation as new scenario types using the vantage-point model from Phase 1.

**Acceptance criteria & test strategy:** Cloud network-topology paths are classified using the same `PathState` values as on-premises paths, with cloud-specific evidence (security-group rule, route-table entry, peering state) cited explicitly. VPN/remote-access boundary tests distinguish configured policy from demonstrated access identically to Phase 2's firewall tests.

**Safety constraints & evidence requirements:** Cloud configuration/telemetry visibility limitations are recorded explicitly (per `network.txt` §1.7). No assumption that a cloud IAM path (identity domain) implies network reachability (network domain), or vice versa — this phase is the primary test of the three-domain separation holding under real cross-domain pressure.

**Definition of done & exit criteria:** At least one cloud-network-topology path and one remote-access/VPN boundary test execute end-to-end with evidence-backed results, and a report-layer example demonstrates correlating (without merging) a Cloud BAS IAM finding with a `networkgraph` connectivity finding for the same account.

### Phase 7 — Sector-Specific Assurance

**Current state:** Missing — no OT/ICS, healthcare, or India/UAE regulatory-mapping code exists anywhere in the repository.

**Reuse / no-rebuild:** Builds on all prior phases' scenario/finding infrastructure. Does not introduce a second scoring or reporting system — sector requirements are configuration (criticality classifications, applicable safety restrictions, regulatory mappings) layered onto the existing finding/evidence model, per `network.txt` §2.4's explicit requirement that sector-specific assessment not collapse into one generic risk score.

**Architecture changes & dependencies:** Depends on Phases 1-6 for the underlying test/evidence capabilities being mapped. Adds: safe OT/ICS network-boundary validation (IT/OT separation, engineering-workstation restrictions, passive/lab-backed testing where active probing risks production safety) and healthcare network-isolation validation (medical-device/clinical-system boundaries, vendor remote-access checks). Adds a versioned regulatory-mapping layer (RBI/SEBI/CERT-In for India, UAE Central Bank and applicable UAE cybersecurity requirements) that maps obligations to relevant controls/simulations/evidence, with source references, effective dates, and applicability conditions — configurable by jurisdiction, sector, entity type, and customer.

**Acceptance criteria & test strategy:** OT/ICS and healthcare tests default to passive/lab-backed execution unless explicit active-test authorization and safety sign-off exist. Regulatory mappings carry traceable source references and version history; mapped findings are traceable to the specific simulation and evidence that satisfies (or fails to satisfy) the mapped obligation.

**Safety constraints & evidence requirements:** Industrial, healthcare, payment, and critical-infrastructure environments receive strictly stronger safeguards than the default (per `network.txt` §9, non-negotiable). A successful simulation or generated report is never presented as proof of regulatory compliance without qualified review (per `network.txt` §3, explicit).

**Definition of done & exit criteria:** At least one OT/ICS-safe test and one healthcare-safe test execute under documented stricter safeguards, and at least one regulatory obligation per jurisdiction (India, UAE) is mapped end-to-end from obligation to control to simulation to evidence, with version/source traceability.

## 5. Cross-Phase Safety & Quality Non-Negotiables

Carried forward verbatim from `network.txt` §9 as binding constraints on every phase above, not aspirational text:

- Explicit authorization and defined target scope required for every run.
- Rate limits, timeouts, abort controls, and resource constraints enforced.
- No destructive actions, credential interception, traffic flooding, or production-disruptive operations in ordinary simulations.
- Synthetic or lab-backed testing used when live validation is unsafe, and always labeled as such.
- Stricter safeguards for industrial, healthcare, payment, and critical-infrastructure environments.
- Observed facts, inferred risks, synthetic evidence, and unverified assumptions are kept visibly separate in every finding.
- A mock/synthetic provider result is never reported as a real security-product test result.
- No claim of complete coverage or regulatory compliance without evidence sufficient to support it.

## 6. Open Questions / Future Phases

- Real network discovery execution (active scanning engines, passive flow collection) is scoped as Phase 2 logic but the specific discovery techniques (and their safety classification per environment) are deferred to Phase 2's own implementation specification.
- Cross-account/cross-tenant correlation for the cloud-networking half of Phase 6 depends on the (currently held) Cloud BAS initiative's account model remaining stable; if Cloud BAS resumes with a materially different account/resource identifier scheme, Phase 6 must re-verify its cross-reference assumption before implementation.
- Whether `internal/networkgraph` needs its own six-state-equivalent enum for domains `PathState`'s existing semantics don't quite fit (e.g., a path that's policy-supported but never testable due to safety restrictions) is left to Phase 1's implementation specification to resolve against real type-design pressure, not decided here.

## Conclusion

Network BAS Mastery extends Audspect into network-layer validation by building one new package (`internal/networkgraph`) that owns network-connectivity truth, reusing `cloudgraph`'s proven `PathState`/`Provenance` vocabulary rather than reinventing it, and extending `detectverify`'s existing connector pattern rather than building parallel control-efficacy infrastructure. The existing identity-path layer (`attackpath`/`admatrix`/`adchain`/`latmove`) and the existing data-movement layer (9 DLP scenarios + sink packages) are preserved untouched as the other two legs of a three-domain evidence model that the reporting layer correlates but never merges. The seven-phase roadmap delivers network discovery, firewall/segmentation validation, multi-hop attack-path analysis, network-security-product efficacy, DNS/protocol security, cloud/remote-access networking, and sector-specific assurance in that order, with every phase gated on repository-verified reuse boundaries and an explicit, evidence-backed definition of done.
