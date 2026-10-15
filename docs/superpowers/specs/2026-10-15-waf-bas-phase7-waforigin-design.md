# WAF BAS Mastery Phase 7: Origin, Deployment and Resilience — Design Spec

## 1. Scope

Per `waf.txt` lines 160-163, Phase 7 is: **"Origin, deployment and resilience — Test routing coverage, direct-origin reachability, fail-open conditions, TLS/proxy behavior, and configuration consistency."**

Unlike Phases 2/5/6 (new attack-payload catalogs) and Phases 3/4 (payload-weakness evaluators), Phase 7 is about **deployment topology and resilience**, not new attack payloads. Its five named items split into three evaluation shapes:

| Named item | Shape |
|---|---|
| routing coverage | bypass pair |
| direct-origin reachability | bypass pair |
| fail-open conditions | bypass pair |
| TLS/proxy behavior | protocol claim (single malicious/benign leg) |
| configuration consistency | cross-node consistency |

New package: `orchestrator/internal/waforigin`.

## 2. Dependency

`waforigin` depends on `internal/wafval` (required: `EvaluateClaim`, `Expectation`, `ClaimPrevention`, `Verdict` family, `Result`, `CollectionResult`, `CorrelationKey`) and `internal/wafcatalog` (read-only cross-reference to existing `AttackVector`s and their `Expectations()` — the attack payload under test in a bypass or consistency scenario is always an existing catalogued vector, never a new one this phase invents). It does **not** depend on `wafpolicygap`, `wafevasion`, `wafapiflow`, or `wafbotabuse`, and none of those depend on it. This mirrors `wafpolicygap`'s and `wafevasion`'s dependency shape (one-way on `wafval` + `wafcatalog`), not `wafapiflow`'s/`wafbotabuse`'s (`wafval`-only), because Phase 7's whole point is evaluating *existing* attacks under topology-weakening conditions — it contributes no new payloads.

## 3. Distinctness from existing phases

- **vs. `wafpolicygap` (Phase 3):** `wafpolicygap`'s baseline/weakened pairs differ by a **policy-rule change** (detection-only mode, exclusion rule, priority conflict) with `PolicyDifferentiationConfirmed` gating `wafval.EvaluatePolicyGap`. Phase 7's bypass pairs differ by a **network-topology or availability condition** (an undocumented route, a path that skips the WAF entirely, the WAF process being unavailable) — nothing about the policy itself changed. The attribution story differs, so Phase 7 defines its **own** local decision function (`decideOriginGap`), mirroring `wafevasion`'s precedent of not reusing `wafval.EvaluatePolicyGap` when the attribution story doesn't match, rather than stretching that function's policy-specific semantics.
- **vs. `wafevasion` (Phase 4):** `wafevasion`'s pairs differ by an **encoding/protocol-framing trick** on the same logical request (origin-equivalent payloads). Phase 7's bypass pairs differ by **which network path the request took**, not by how the payload inside it is encoded.
- **vs. `wafbotabuse` BOTABUSE-004 (Phase 6):** both involve multiple nodes, but BOTABUSE-004 is about **runtime counter/lockout state** consistency (does node A know what node B counted). Phase 7's configuration-consistency item is about **policy/ruleset version** consistency (does node A enforce the same rule as node B on a single request, independent of any counter). No shared code; both are fixture-backed scenarios over the same general "ask wafval twice, compare" shape, each owning its own comparison.

## 4. Types

### 4.1 Weakness taxonomy

```go
type WeaknessKind string
const (
    KindBypassPair           WeaknessKind = "bypass_pair"
    KindProtocolClaim        WeaknessKind = "protocol_claim"
    KindCrossNodeConsistency WeaknessKind = "cross_node_consistency"
)

type WeaknessType string
const (
    WeaknessRoutingCoverageGap       WeaknessType = "routing_coverage_gap"
    WeaknessDirectOriginReachability WeaknessType = "direct_origin_reachability"
    WeaknessFailOpenOnUnavailability WeaknessType = "fail_open_on_waf_unavailability"
    WeaknessTLSProxyBehavior         WeaknessType = "tls_proxy_behavior"
    WeaknessConfigurationConsistency WeaknessType = "configuration_consistency"
)

func (w WeaknessType) Kind() WeaknessKind // maps each constant to its Kind; unknown input returns ""
```

### 4.2 Kind A — `BypassScenario` (routing coverage, direct-origin reachability, fail-open)

```go
type BypassScenario struct {
    ID                 string
    Weakness           WeaknessType // must satisfy Weakness.Kind() == KindBypassPair
    AttackVectorID      string       // cross-references a real wafcatalog.AttackVector
    BaselinePathDescription string   // the documented, WAF-fronted path (e.g. "https://app.example.com/search via the production CDN/WAF edge")
    BypassPathDescription   string   // how the bypass path differs (e.g. "direct request to the origin's public IP, skipping the CDN/WAF edge entirely")
    Provenance          string
}

func NewBypassScenario(id string, weakness WeaknessType, attackVectorID string, baselinePathDescription string, bypassPathDescription string, provenance string) (BypassScenario, error)
```

Validation: `id` non-empty; `weakness.Kind() == KindBypassPair` (rejects a `WeaknessType` from another kind, and rejects an unknown `WeaknessType` value); `attackVectorID` non-empty; `baselinePathDescription` non-empty; `bypassPathDescription` non-empty; `provenance` non-empty.

### 4.3 Kind B — `ProtocolBehaviorVector` (TLS/proxy behavior)

Mirrors `wafbotabuse.BotAbuseVector`'s construction-validation shape exactly (same checks, same order), scoped to this phase's single named item:

```go
type RequestTemplate struct {
    Method, Path, PayloadLocation, Payload, Description string
}
type StandardsMapping struct {
    CWEIDs           []string
    WSTGCategory     string
    Top10Category    string
    APITop10Category string
    ATTACKTechniques []string
}
type ProtocolBehaviorVector struct {
    ID                        string
    Version                   int
    Name                      string
    Preconditions             string
    Malicious                 RequestTemplate
    BenignCounterpart         *RequestTemplate
    NoBenignCounterpartReason string
    Standards                 StandardsMapping
    Provenance                string
}

func NewProtocolBehaviorVector(id string, version int, name string, preconditions string, malicious RequestTemplate, benignCounterpart *RequestTemplate, noBenignCounterpartReason string, standards StandardsMapping, provenance string) (ProtocolBehaviorVector, error)
```

Validation identical in substance to `wafbotabuse.NewBotAbuseVector` (minus the category check, since this kind has exactly one named item and a `Category` enum of one value is dead machinery): `id` non-empty, `version >= 1`, `Malicious.{Method,Path,Description}` non-empty, every `Standards.CWEIDs` entry matches `^CWE-\d+$`, `Standards` has at least one mapping field set, `Provenance` non-empty, exactly one of `BenignCounterpart`/`NoBenignCounterpartReason` set (and `BenignCounterpart`, if set, independently valid).

### 4.4 Kind C — `ConsistencyScenario` (configuration consistency)

```go
type ConsistencyScenario struct {
    ID             string
    AttackVectorID string // cross-references a real wafcatalog.AttackVector
    Provenance     string
}
func NewConsistencyScenario(id string, attackVectorID string, provenance string) (ConsistencyScenario, error)

type NodeEvidence struct {
    NodeID   string
    Evidence []wafval.CollectionResult
    Key      wafval.CorrelationKey
}

type ConsistencyVerdict string
const (
    ConsistencyConfirmed    ConsistencyVerdict = "confirmed"      // >=2 trustworthy node results, all verdicts agree
    ConsistencyDrift        ConsistencyVerdict = "drift_detected" // >=2 trustworthy node results, verdicts disagree
    ConsistencyInconclusive ConsistencyVerdict = "inconclusive"   // fewer than 2 trustworthy node results
)
```

Validation for `NewConsistencyScenario`: `id` non-empty, `attackVectorID` non-empty, `provenance` non-empty.

## 5. Evidence / evaluation

### 5.1 Kind A — `EvaluateBypassScenario`

```go
func EvaluateBypassScenario(
    scenario BypassScenario,
    vector wafcatalog.AttackVector,
    policyBasis string,
    baselineEvidence []wafval.CollectionResult, baselineKey wafval.CorrelationKey,
    bypassEvidence []wafval.CollectionResult, bypassKey wafval.CorrelationKey,
) (wafval.Verdict, string, error)
```

Checks `vector.ID == scenario.AttackVectorID` (else error, mirroring `wafpolicygap.checkVectorMatch`). Takes the vector's malicious-leg `Expectation` (`vector.Expectations(policyBasis)[0].Expectation`), evaluates it against both evidence sets via `wafval.EvaluateClaim`, then calls a **locally owned** `decideOriginGap(baseline, bypass wafval.Result) (wafval.Verdict, string)`:

- Gate: if the baseline leg is not a trustworthy block (`trustworthyBlocked`, defined locally exactly as `wafevasion`'s: `Verdict == VerdictBlocked && (Confidence == ConfidenceHigh || Confidence == ConfidenceMedium)`), return `VerdictInconclusive, "baseline did not establish a reliable block through the documented path; bypass-leg behavior cannot be attributed to the bypass condition"`.
- Else switch on the bypass leg's verdict (the malicious leg's claim is always `ClaimPrevention`, so `VerdictAllowed` — reserved for `ClaimFalsePositive` — is never a reachable value here, exactly as in `wafval.derivePrevention`): `VerdictBlocked` → `VerdictBlocked, "the bypass path did not succeed in evading enforcement -- the same attack was still blocked"`; `VerdictMissed` (the gap case: the attack reached the origin neither detected nor blocked via this path) → `VerdictMissed, "bypass confirmed: the same attack reached the origin neither detected nor blocked via this path"`; `VerdictDetectedButAllowed` → `VerdictDetectedButAllowed, "the bypass path logged the attack but still allowed it through -- partial coverage gap"`; anything else/low-confidence → `VerdictInconclusive, "insufficient evidence to determine whether the bypass path is covered"`.

### 5.2 Kind B — `ProtocolBehaviorVector.Expectations`

```go
func (v ProtocolBehaviorVector) Expectations(policyBasis string) []ProtocolLegExpectation
```

Identical leg-ordering/claim-mapping contract to every prior catalog's `Expectations`: malicious leg always first with `wafval.ClaimPrevention`; benign leg appended only when `BenignCounterpart != nil`, with `wafval.ClaimFalsePositive`; never padded.

### 5.3 Kind C — `EvaluateConfigurationConsistency`

```go
func EvaluateConfigurationConsistency(scenario ConsistencyScenario, vector wafcatalog.AttackVector, policyBasis string, nodes []NodeEvidence) (ConsistencyVerdict, string, error)
```

Checks `vector.ID == scenario.AttackVectorID`. For each node, evaluates the vector's malicious-leg `Expectation` via `wafval.EvaluateClaim(expectation, node.Evidence, node.Key)`, keeping only trustworthy results (same local `trustworthyBlocked`-style check, generalized to "Confidence is High or Medium" regardless of Verdict, since a trustworthy *Allowed* result is just as comparable as a trustworthy *Blocked* one). If fewer than 2 trustworthy results remain, returns `ConsistencyInconclusive, "fewer than 2 nodes produced trustworthy evidence"`. Otherwise compares the trustworthy results' `Verdict` values: all equal → `ConsistencyConfirmed, "<N> nodes agree on verdict <V>"`; any differ → `ConsistencyDrift, "node <A> produced <VerdictA> while node <B> produced <VerdictB>"` (naming the first disagreeing pair). This adds zero new `wafval` verdict-derivation logic — it only compares `Verdict` values `wafval.EvaluateClaim` already derived.

## 6. Seed catalog

One scenario per named item, cross-referencing real `wafcatalog` vectors (confirmed present in `orchestrator/internal/wafcatalog/catalog_injection.go` and `catalog_network.go`):

| ID | Weakness / Kind | Cross-referenced vector | Story |
|---|---|---|---|
| WAFORIGIN-001 | routing_coverage_gap (bypass pair) | SQLI-001 | Same SQLi payload sent to an undocumented secondary vhost/subpath that was never registered with the WAF, vs. the documented route. |
| WAFORIGIN-002 | direct_origin_reachability (bypass pair) | XSS-001 | Same XSS payload sent directly to the origin's own IP/hostname, bypassing the CDN/WAF edge entirely, vs. through the documented edge. |
| WAFORIGIN-003 | fail_open_on_waf_unavailability (bypass pair) | SSRF-001 | Same SSRF payload sent while the WAF reports an internal error/timeout/unavailable state, vs. while the WAF is healthy. |
| WAFORIGIN-004 | tls_proxy_behavior (protocol claim) | (standalone `ProtocolBehaviorVector`) | Malicious: request using a deprecated TLS 1.0 handshake with a forged `X-Forwarded-Proto: https` header while actually arriving over plaintext. Benign: request using the declared-minimum TLS version (1.2+) with correctly-set proxy headers. CWE-319 (Cleartext Transmission). |
| WAFORIGIN-005 | configuration_consistency (cross-node) | PATHTRAV-001 | Same path-traversal payload's evidence collected independently from 2 (fixture) deployment nodes; asserts both nodes' independently-derived verdicts agree. |

## 7. Acceptance gate

1. `NewBypassScenario` rejects: empty ID; a `WeaknessType` whose `Kind() != KindBypassPair` (including an unknown value); empty `AttackVectorID`/`BaselinePathDescription`/`BypassPathDescription`/`Provenance`.
2. `NewProtocolBehaviorVector` rejects the same construction-time violations as `wafbotabuse.NewBotAbuseVector` (empty ID, version<1, empty malicious fields, malformed CWE ID, standards-all-empty, empty provenance, both-or-neither benign/reason, invalid benign counterpart).
3. `NewConsistencyScenario` rejects empty ID/AttackVectorID/Provenance.
4. `ProtocolBehaviorVector.Expectations` returns exactly 1 or 2 legs, never padded.
5. `EvaluateBypassScenario` rejects a vector/scenario ID mismatch; returns `VerdictInconclusive` when baseline isn't a trustworthy block; returns `VerdictMissed` when the bypass leg's evidence shows the attack reached the origin neither detected nor blocked (the gap case).
6. `EvaluateConfigurationConsistency` rejects a vector/scenario ID mismatch; returns `ConsistencyInconclusive` with fewer than 2 trustworthy node results; returns `ConsistencyDrift` when two trustworthy results disagree; returns `ConsistencyConfirmed` when all trustworthy results agree.
7. All 5 seed scenarios/vectors construct without error and cross-reference vector IDs that genuinely exist in `wafcatalog.AudspectWAFAttackCatalog()`.

## 8. Deferred (explicitly, per standing fixture-backed discipline)

- Real network-topology discovery (actually enumerating undocumented routes/vhosts) — this phase only models the claim shape once such a route is already known to exist.
- A real multi-node deployment to collect genuine cross-node evidence from (Kind C is fixture-backed: `NodeEvidence` is caller-supplied, not independently gathered here).
- Real TLS handshake fuzzing/negotiation — WAFORIGIN-004 models the claim shape of a protocol-downgrade probe, not a live TLS stack.
- Expanding the seed catalog beyond 1 scenario per named item.
- Any new `wafval` verdict-derivation logic — Kind A's `decideOriginGap` and Kind C's comparison are both local, built only on `wafval.EvaluateClaim`'s existing output.
