# WAF BAS Mastery Phase 6: Bot, Abuse and Rate-Limit Efficacy — `internal/wafbotabuse` Design

**Status:** Approved for implementation under the user's standing authorization to complete all WAF BAS Mastery phases autonomously ("fix any critical or important findings then move to the next phase without approval start spec plan and native" / "keep going until all phases are done"). Condensed self-directed brainstorm — no interactive Q&A round; design decisions below are this session's own reasoned choices, made explicit for review.

## 1. Scope (from `waf.txt`)

> Phase 6 — Bot, abuse and rate-limit efficacy
> Validate bounded automation scenarios, rate limits, credential-abuse controls, and distributed enforcement.

## 2. Package shape: a third sibling catalog, not a new evaluation rule

Like Phase 5, none of these four items need a new comparison rule. Each is answerable by the same single-request-vs-benign-counterpart shape `wafcatalog`/`wafapiflow` already use: a request that crosses a declared volume/rate/behavioral threshold, evaluated through the unmodified `wafval.EvaluateClaim` pipeline. The "burst" or "window" context that makes a request a violation (e.g. "the 101st request in 60 seconds," "the 21st failed login in 5 minutes") is documented in the vector's `Preconditions`/`Malicious.Description` fields, the same documentary-fixture level of detail Phase 4's evasion pairs and Phase 5's workflow-replay pair already use — no new multi-request sequence data structure is needed.

So Phase 6 is `internal/wafbotabuse`: a third sibling of `internal/wafcatalog` and `internal/wafapiflow` under `internal/wafval`, not a consumer of either:

```
wafval ← wafcatalog    (Phase 2)
wafval ← wafapiflow    (Phase 5)
wafval ← wafbotabuse   (Phase 6)
```

Zero new `wafval` verdict logic. No dependency on `wafcatalog`, `wafpolicygap`, `wafevasion`, or `wafapiflow`.

## 3. Deliberately distinct from existing vectors

Phase 2's `wafcatalog` already seeded `FamilyRateLimit` (RATE-001/002) and `FamilyAuthAbuse`'s AUTH-001 (credential stuffing). Phase 5's `wafapiflow` seeded `resource_control` (APIFLOW-005, an unbounded *per-request quantity* parameter). Phase 6's four vectors are chosen to be genuinely distinct from all of these:

- **Bounded automation** is about the *absence of human/browser behavioral signals* (timing, JS-challenge cookies, standard headers) across a burst of otherwise individually-benign requests — a claim about client behavior, not payload content or request volume. No existing vector models this at all.
- **Rate limit** here is about a *request-count-per-time-window* threshold (e.g. 500 requests/60s), distinct from Phase 5's `resource_control` (a single request's *quantity parameter*, e.g. `?limit=999999999`) and from Phase 2's RATE-001/002 (which this phase's own vector is a parallel instance of, not a restatement — RATE-001/002 already exist and are left untouched; Phase 6 adds one more rate-limit-shaped scenario under its own category taxonomy for this phase's four-category structure).
- **Credential-abuse controls** here is about *failed-attempt-count-triggered lockout/CAPTCHA* over a window, distinct from AUTH-001 (a single request's *credential-stuffing payload signature*) — this vector asks whether volume triggers a control, not whether a payload looks like an attack.
- **Distributed enforcement** is about whether a *shared/global* threshold (lockout count, rate-limit count) is actually enforced consistently across multiple backend nodes, or only locally per node — bypassable by round-robin distribution. No existing vector covers cross-node consistency at all.

## 4. Core types

Identical shape to `wafapiflow`'s (which itself mirrors `wafcatalog`'s), redefined locally — no import of any sibling catalog package:

```go
type BotAbuseCategory string

const (
    CategoryBoundedAutomation      BotAbuseCategory = "bounded_automation"
    CategoryRateLimit              BotAbuseCategory = "rate_limit"
    CategoryCredentialAbuse        BotAbuseCategory = "credential_abuse"
    CategoryDistributedEnforcement BotAbuseCategory = "distributed_enforcement"
)

type Severity string // Critical, High, Medium, Low -- same four levels as the other catalogs

type RequestTemplate struct {
    Method          string
    Path            string
    PayloadLocation string
    Payload         string
    Description     string
}

type StandardsMapping struct {
    CWEIDs           []string
    WSTGCategory     string
    Top10Category    string
    APITop10Category string
    ATTACKTechniques []string
}

// BotAbuseVector owns both a malicious RequestTemplate and, structurally,
// its benign counterpart -- exactly one of BenignCounterpart or
// NoBenignCounterpartReason is set, never both, never neither, enforced at
// construction (identical discipline to wafcatalog.AttackVector and
// wafapiflow.APIFlowVector).
type BotAbuseVector struct {
    ID                        string
    Version                   int
    Category                  BotAbuseCategory
    Name                      string
    Severity                  Severity
    Preconditions             string
    Malicious                 RequestTemplate
    BenignCounterpart         *RequestTemplate
    NoBenignCounterpartReason string
    Standards                 StandardsMapping
    Provenance                string
}
```

`NewBotAbuseVector(id, version, category, name, severity, preconditions, malicious, benignCounterpart, noBenignCounterpartReason, standards, provenance) (BotAbuseVector, error)` validates identically to `wafcatalog.NewAttackVector`/`wafapiflow.NewAPIFlowVector`: ID non-empty, `Version >= 1`, known `Category`/`Severity`, `Malicious` fields non-empty, every `Standards.CWEIDs` entry matches `^CWE-\d+$`, `Standards` has at least one of its four mapping fields set, `Provenance` non-empty, and exactly one of `BenignCounterpart`/`NoBenignCounterpartReason`.

## 5. Catalog-wide validation

`ValidateBotAbuseCatalog(vectors []BotAbuseVector) error` rejects a catalog containing two vectors with the same ID — the same single-purpose duplicate-ID guard every catalog package in this project uses.

## 6. Evidence/evaluation integration

```go
type BotAbuseLeg string

const (
    LegMalicious BotAbuseLeg = "malicious"
    LegBenign    BotAbuseLeg = "benign"
)

type BotAbuseLegExpectation struct {
    VectorID    string
    Leg         BotAbuseLeg
    Request     RequestTemplate
    Expectation wafval.Expectation
}

// Expectations returns exactly 1 entry (malicious only) or 2 entries
// (malicious + benign) -- never padded -- mirroring
// wafcatalog.AttackVector.Expectations / wafapiflow.APIFlowVector.Expectations
// exactly. The malicious leg is always first and always present.
func (v BotAbuseVector) Expectations(policyBasis string) []BotAbuseLegExpectation
```

Each leg's `wafval.Expectation` carries `Claim: wafval.ClaimPrevention` for the malicious leg and `Claim: wafval.ClaimFalsePositive` for the benign leg (when present) — identical to the other two catalogs' mapping.

## 7. Seed catalog

`AudspectWAFBotAbuseCatalog() ([]BotAbuseVector, error)` returns exactly 4 vectors, one per `BotAbuseCategory`, proving the model rather than attempting exhaustive breadth (same discipline as Phases 3-5's 1-per-category seed catalogs):

| ID | Category | Malicious / benign sketch | Standards |
|----|----------|------------------------------|-----------|
| BOTABUSE-001 | bounded_automation | a 25-requests/sec burst of otherwise-valid search requests missing the JS-challenge cookie and a standard browser User-Agent vs. a single human-paced request carrying both | CWE-799 |
| BOTABUSE-002 | rate_limit | the 501st order-creation request within 60 seconds from one API key (500/60s declared limit) vs. a single request well within that limit | CWE-770 |
| BOTABUSE-003 | credential_abuse | the 21st failed login attempt within 5 minutes against one username (20-failure/5min declared threshold), no lockout triggered vs. a single login attempt with no prior failure history | CWE-307 |
| BOTABUSE-004 | distributed_enforcement | 20 failed login attempts against one username, split 5-at-a-time round-robin across 4 backend nodes so no single node locally sees more than 5 failures vs. the same 20 attempts evaluated against genuinely shared distributed lockout state | CWE-799 |

## 8. Acceptance gate

1. `NewBotAbuseVector` rejects: empty ID, `Version < 1`, unknown `Category`, unknown `Severity`, empty `Malicious.*` fields, a `Standards.CWEIDs` entry not matching `^CWE-\d+$`, `Standards` with all four mapping fields empty, empty `Provenance`, both `BenignCounterpart` and `NoBenignCounterpartReason` set, and neither set.
2. `ValidateBotAbuseCatalog` rejects a catalog with two vectors sharing an ID.
3. `Expectations` returns exactly 1 entry when `NoBenignCounterpartReason` is set and exactly 2 when `BenignCounterpart` is set — never 0, never padded.
4. `AudspectWAFBotAbuseCatalog` returns exactly 4 vectors, one per distinct `BotAbuseCategory`, and the aggregator's own `ValidateBotAbuseCatalog` call passes on its output.

## 9. Explicitly deferred

- Real execution against a live edge/WAF deployment, a real multi-node backend, and real timing/burst generation to actually send these request sequences and observe enforcement.
- Expanding the seed catalog beyond one example per category.
- Real browser-fingerprint/behavioral-signal collection (JS-challenge verification, timing-distribution analysis) — this phase models the *attack shape* as a documentary `RequestTemplate`, the same level of detail every other catalog package in this project uses; a real bot-detection harness is real-execution work, out of scope here.
- Any new `wafval` verdict logic, any dependency on `wafcatalog`/`wafpolicygap`/`wafevasion`/`wafapiflow`, and any literal multi-request sequence/session data structure — each vector's `Preconditions`/`Description` documents the burst/window context at the fixture level, without needing to model a session state machine.
