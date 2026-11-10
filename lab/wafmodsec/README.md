# wafmodsec lab

A real, self-hosted ModSecurity + OWASP CRS WAF, run as a live target for
`internal/wafmodsec`/`internal/vendors/modsecwaf` -- Audspect's own real
(non-fixture) WAF-vendor adapter. This closes `docs/waf-mastery-qa-log.md`
item #1 for one engine: no vendor account, tenant, or signup is needed,
because ModSecurity + OWASP CRS is an open-source engine we run entirely
ourselves, the same self-owned-target philosophy `internal/apibas/lab`
already uses elsewhere in this repo.

## What's here

- `docker-compose.yml` -- two services, both pinned by image digest:
  - `origin`: `mendhak/http-https-echo`, a permissive HTTP server that
    answers every request 200 and echoes back what it received as JSON.
    It never implements any real application logic -- it only needs to
    prove whether a request reached it.
  - `waf`: `owasp/modsecurity-crs` (nginx variant), proxying to `origin`,
    running real ModSecurity + OWASP CRS v4 rule enforcement at
    `BLOCKING_PARANOIA=1` / `ANOMALY_INBOUND=5` (CRS defaults).
- `smoke.sh` -- a quick curl-based check that the lab behaves as expected
  (4 real `wafcatalog` vectors, malicious blocked / benign allowed).

## Running it

```sh
docker compose up -d        # from this directory
bash smoke.sh                # sanity-check it
```

The WAF listens on `http://localhost:8888`. `origin` is not published to
the host -- every request must go through `waf` to mean anything.

```sh
# malicious -> blocked by ModSecurity, origin never sees it
curl -i "http://localhost:8888/search?q=%27%20UNION%20SELECT%20NULL--"
# benign -> allowed through, origin's own echo comes back
curl -i "http://localhost:8888/search?q=hello"
```

```sh
docker compose down -v       # tear down
```

## Running the Go live test against it

`internal/wafmodsec`'s live test is skipped unless `WAF_MODSEC_LAB_URL` is
set, so it never runs as part of the normal `go test ./...` suite:

```sh
WAF_MODSEC_LAB_URL=http://localhost:8888 \
  go test ./internal/wafmodsec/... -run TestLive -v
```

This drives 4 real `wafcatalog` vectors (one per family that only needs
the `""` / `query:<param>` `PayloadLocation` forms `modsecwaf.BuildRequest`
implements today: `SQLI-001`, `XSS-001`, `PATHTRAV-001`, `HTTPPARSE-002`)
through the real HTTP round trip, both malicious and benign legs, and
asserts the real `wafval.Verdict` each one resolves to.

## Running a real enterprise scenario against it

`internal/wafmodsec/exploitprevention.go`'s `BuildExploitPreventionLiveFixtures`
wires 3 of `wafassessment.AudspectExploitPreventionScenario`'s 8 contributing
vectors (`SQLI-001`, `XSS-001`, `PATHTRAV-001` -- the ones `BuildRequest` can
replay) to this live lab instead of a hand-authored fixture, then hands the
result to the real, unmodified `wafassessment.EvaluateScenario`:

```sh
WAF_MODSEC_LAB_URL=http://localhost:8888 \
  go test ./internal/wafmodsec/... -run TestLive_ExploitPreventionScenario -v
```

The other 5 vectors get no fixture at all, so they surface through
`ScenarioResult.UntestedVectorIDs` -- the scenario's real outcome against
live evidence is `ScenarioIncomplete` (3 genuinely `Blocked`, 5 genuinely
untested), never silently upgraded to `ScenarioPass`.

## Hitting it over HTTP

`GET /api/waf/scenarios/exploit-prevention/live` serves exactly the above,
through `internal/wafmodsec.RunExploitPreventionLive`, in the same JSON
shape as every other `/api/waf/scenarios/<slug>` route. It needs
`WAF_MODSEC_LAB_URL` set in the *server's own environment* (not the
request) -- unset, it returns `503` naming the variable rather than
silently serving the fixture-backed result; an unreachable lab returns
`502`. Every assertion it returns carries `"evidenceSource":"live_execution"`,
never `"fixture"` -- see `wafassessment.VectorFixture.EvidenceSource`.

```sh
WAF_MODSEC_LAB_URL=http://localhost:8888 \
  go test ./internal/api/... -run TestWafExploitPreventionLiveJSONHandler -v
```

## Wired into the other 9 enterprise scenarios -- partially

Beyond exploit-prevention, 4 more scenarios now have *some* live-capable
vectors, each with its own `Run<Scenario>Live(ctx, client)` in
`internal/wafmodsec`, same pattern as `RunExploitPreventionLive`:

| Scenario | Live vectors | Verdicts (confirmed against the real lab) |
|---|---|---|
| `http-protocol-integrity` | `HTTPPARSE-002` (1/3) | `Blocked` |
| `routing-cache-integrity` | `CACHE-002`, `CACHE-003` (2/3) | `Inconclusive`, `Blocked` |
| `api-protection` | `API-003`, `APIFLOW-005` (2/8) | `Inconclusive`, `Inconclusive` |
| `legitimate-traffic` | `SQLI-001`, `XSS-001`, `PATHTRAV-001`, `RATE-001` benign legs (4/6) | all `Allowed` |
| `file-upload-content-trust` | `FILEUP-001`, `FILEUP-003` (2/3) | `Inconclusive`, `Blocked` |

`api-protection`'s `APIFLOW-005` comes from `internal/wafapiflow`, a
sibling catalog to `wafcatalog` with its own, structurally identical
`RequestTemplate` type -- `apiflowToWafcatalogTemplate` in
`internal/wafmodsec/apiprotection.go` converts between them so one
`modsecwaf.Client` can drive vectors from either catalog; `modsecwaf`
itself did not need to change. `legitimate-traffic` drives each vector's
BENIGN counterpart, not its malicious payload -- it evaluates
`wafval.ClaimFalsePositive`, and `BuildCollectionResults` is claim-agnostic,
so no change was needed there either.

The `CACHE-002`/`API-003`/`APIFLOW-005`/`FILEUP-001` `Inconclusive` verdicts
are a real, confirmed finding, not an adapter gap: CRS genuinely allows all
four through (200, verified by curl against the running container) because
it has no business-logic, cache-layer, or (at this paranoia level)
upload-content-inspection awareness to catch a static-extension
cache-deception trick, a `fields=*` over-exposure, an absurd `limit=`
value, or a PHP web shell hidden in an uploaded file's content -- an
honest statement about this specific generic WAF engine's configured
scope, not a bug anywhere in this chain.

`file-upload-content-trust` needed `modsecwaf.BuildRequest` to grow real
multipart/form-data support (`"body:multipart:<field>"`): `<field> ==
"filename"` means Payload is the file's NAME (so `FILEUP-003`'s path
traversal travels verbatim in the real `Content-Disposition` header, which
CRS's generic traversal rule catches regardless of which field carries it
-- `Blocked`); any other `<field>` means Payload is the file's CONTENT,
under a fixed filename (so `FILEUP-001`'s PHP web shell is the literal
uploaded bytes). `FILEUP-002` (a decompression-bomb archive) stays
unwired: its catalog `Payload` is a human description
("`<highly compressed archive engineered to expand to many GB on
extraction>`"), not real bytes, and this lab's origin has no
archive-extraction logic for a bomb to even detonate against -- there is
no honest way to replay this one yet, even with multipart support in
place.

```sh
WAF_MODSEC_LAB_URL=http://localhost:8888 \
  go test ./internal/wafmodsec/... -run TestLive_ -v
```

**4 scenarios get NO live wiring, for real, disclosed reasons -- not an
oversight:**
- `automated-abuse` (`RATE-001/002`, `BOTABUSE-001..004`): every vector is
  a multi-request, timed-burst/behavioral claim ("50 requests in 2
  seconds", "501st request within a 60-second window") -- genuinely
  testing it needs a harness that fires a bounded sequence over a window
  and watches when enforcement kicks in, not `modsecwaf.Client`'s
  single-request `Send`. Driving one request and calling it a test of
  rate-limit enforcement would be a false claim, not a thin slice.
- `detection-telemetry` (`WAFDETECT-001..005`): evidence is SIEM/alert
  pipeline completeness and timing (event-to-alert latency, archive
  completeness) -- there is no HTTP request to replay at all; this needs
  a real alerting backend, not a WAF.
- `origin-resilience` (`WAFORIGIN-001..005`): deployment-topology claims
  (direct-origin reachability, fail-open behavior, cross-node config
  consistency) that need a multi-node/dual-path network setup this lab's
  single WAF-fronted, non-host-exposed origin doesn't have.
- `policy-integrity` (`GAP-001..006`): a genuine two-leg
  baseline-vs-weakened policy COMPARISON (`wafpolicygap.EvaluatePolicyGap`)
  -- this lab has exactly one fixed CRS configuration, so there is no
  second, deliberately-weakened policy to compare against yet.

## What this proves, and what it doesn't (yet)

**Proves:** a genuinely live adapter chain --
`modsecwaf.Client.Send` (real HTTP) ->
`wafmodsec.BuildCollectionResults` (real response -> `wafval.Observation`) ->
`wafval.EvaluateClaim` (real verdict) -- working end to end against a real,
running WAF engine, across 6 enterprise scenarios now. This is a stronger
resolution than `internal/avdefender`'s own precedent (the Defender bridge
was built but never run against a live tenant); this one has actually been
run, live, in this session.

**Does not (yet) prove / cover:**
- Only a handful of the catalog's 65+ vectors are wired -- the ones whose
  `PayloadLocation` is `""`, `query:<param>`, or `body:multipart:<field>`.
  Header-based (`header:X-Forwarded-Host`) and other body-based
  (`body:json:...`, `body:xml:...`) forms are real gaps in
  `modsecwaf.BuildRequest`, documented there, not silently unsupported.
- `wafmodsec` never parses ModSecurity's audit log, so it never asserts
  `wafval.DetectionMatched`/`DetectionNotMatched` -- an allowed-through
  malicious request resolves to `VerdictInconclusive` under
  `ClaimPrevention`, not `VerdictMissed`, until that follow-up lands.
- Wired into exactly one `internal/api` route
  (`GET /api/waf/scenarios/exploit-prevention/live`) -- the other 4
  partially-live scenarios above have no API route yet, so the console UI
  still only ever shows the fixture-backed result for them. `wafassessment`
  needed two small, backward-compatible fixes to support this honestly:
  `VectorFixture` gained an `EvidenceSource` field (previously hardcoded
  to `EvidenceSourceFixture` on every assertion, in BOTH
  `EvaluateScenarioWithSeverities` and `EvaluateLegitimateTrafficScenario`
  -- the same bug existed in two places) so a caller driving real traffic
  can mark its own evidence `EvidenceSourceLiveExecution` instead --
  every existing hand-authored fixture leaves it unset and still defaults
  to `EvidenceSourceFixture`, so nothing else changed behavior.
  `wafassessment` still performs no I/O itself: the live-wiring glue lives
  entirely in `internal/wafmodsec`, which calls `wafassessment`'s real,
  unmodified evaluators exactly like any other caller would.
- CRS doesn't have rules for every `wafcatalog` family by design (e.g. no
  generic WAF engine inspects cache-key composition) -- some vectors
  (`CACHE-*`) would likely never show a real block against this specific
  engine, which is an honest fact about CRS's scope, not a bug in the
  adapter.
