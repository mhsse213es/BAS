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
- `nginx/00-limit-req-zone.conf`, `nginx/default.conf` -- mounted into the
  `waf` container's own documented template directory, adding a real
  per-client nginx `limit_req` zone (`rate=2r/s burst=3 nodelay`),
  deliberately scoped to exactly `/api/quote` (an exact-match `location`,
  not the generic `location /`) so `automated-abuse`'s `RATE-001` has an
  actual rate limit to test against without rate-limiting every other
  live test's own path -- see each file's own doc comment for exactly how
  and why this is safe, including a real cross-test contamination bug
  this scoping fixes.

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
| `automated-abuse` | `RATE-001` (1/6) | `Blocked` |

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

`automated-abuse`'s `RATE-001` needed two new pieces: a real nginx
`limit_req_zone`/`limit_req` (`nginx/00-limit-req-zone.conf` +
`nginx/default.conf`, mounted into the `waf` container via its own
template mechanism -- see those files' own doc comments for exactly how
and why that's safe) so there is an actual rate limit to test against,
since CRS itself does not do rate limiting; and
`modsecwaf.Client.SendBurst`, which fires a real, bounded burst of N
concurrent requests (10, deliberately exceeding the zone's `rate=2r/s
burst=3`) -- a single `Client.Send` round trip cannot represent "N
requests in a short window" at all, so this is genuinely new capability,
not a wiring change. `wafmodsec.BuildBurstCollectionResults` turns that
burst's responses into the same two `wafval.CollectionResult` mechanisms
`BuildCollectionResults` derives from one response, but must keep the
WAF-engine and origin-app mechanisms pointed at the SAME subset of
requests (the blocked ones when any fired, the allowed ones when none
did) -- reporting "some reached origin" and "some were blocked" as two
independent facts describes two different requests as one event and
resolves `Inconclusive` by contradiction instead of the real finding.
Curl-confirmed against the real container: a burst of 10 to `/api/quote`
returns some `200`s then `503`s once the declared limit is exceeded.

The `limit_req` directive is deliberately in its own `location = /api/quote`
block, not the generic `location /` -- a real cross-test contamination bug
this fixed: putting it in `location /` rate-limited every OTHER live
test's path too (same client IP, same shared container across a whole
test run), surfacing as false `incorrectly_blocked` results on
unrelated vectors. `TestLive_AutomatedAbuseScenario_OneOfSixVectorsLive`
also sleeps 3s after its burst so the leaky bucket fully drains before
any later live test in the same process shares `/api/quote` again (only
`legitimate-traffic`'s `RATE-001` benign leg does, today) -- test-isolation
hygiene, not a production concern.

`RATE-002` and all 4 `BOTABUSE-*` vectors remain unwired; see below for
why each is a bigger, different piece of work than this one was.

```sh
WAF_MODSEC_LAB_URL=http://localhost:8888 \
  go test ./internal/wafmodsec/... -run TestLive_ -v
```

**3 scenarios get NO live wiring, for real, disclosed reasons -- not an
oversight:**
- `automated-abuse`'s other 5 vectors (`RATE-002`, `BOTABUSE-001..004`):
  `RATE-002` needs per-account aggregation across sessions/source
  addresses this lab's origin has no concept of; `BOTABUSE-001` needs a
  bot-management/JS-challenge layer CRS does not provide; `BOTABUSE-002`
  needs a second, header-keyed rate-limit zone; `BOTABUSE-003/004` need
  real stateful lockout/CAPTCHA logic at the origin, and `BOTABUSE-004`
  specifically needs the same multi-node topology `origin-resilience`
  below is blocked on. Each is a materially different, bigger build than
  the single `limit_req` zone `RATE-001` needed.
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
running WAF engine, across 7 enterprise scenarios now. This is a stronger
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
