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

## What this proves, and what it doesn't (yet)

**Proves:** a genuinely live adapter chain --
`modsecwaf.Client.Send` (real HTTP) ->
`wafmodsec.BuildCollectionResults` (real response -> `wafval.Observation`) ->
`wafval.EvaluateClaim` (real verdict) -- working end to end against a real,
running WAF engine, for 4 vectors across 4 families. This is a stronger
resolution than `internal/avdefender`'s own precedent (the Defender bridge
was built but never run against a live tenant); this one has actually been
run, live, in this session.

**Does not (yet) prove / cover:**
- Only 4 of the catalog's 65 vectors are wired -- the ones whose
  `PayloadLocation` is `""` or `query:<param>`. Header-based
  (`header:X-Forwarded-Host`), body-based (`body:json:...`), and
  multipart-based (`body:multipart:...`) forms are real gaps in
  `modsecwaf.BuildRequest`, documented there, not silently unsupported.
- `wafmodsec` never parses ModSecurity's audit log, so it never asserts
  `wafval.DetectionMatched`/`DetectionNotMatched` -- an allowed-through
  malicious request resolves to `VerdictInconclusive` under
  `ClaimPrevention`, not `VerdictMissed`, until that follow-up lands.
- Wired into exactly ONE scenario (`AudspectExploitPreventionScenario`,
  3 of its 8 vectors) -- not the other 9 enterprise scenarios, and not any
  `internal/api` handler, so a console user still sees the fixture-backed
  result, not this live one. `wafassessment` itself was NOT modified to do
  this: `BuildExploitPreventionLiveFixtures` lives entirely in
  `internal/wafmodsec` and calls `wafassessment.EvaluateScenario` exactly
  like any other caller would, by design -- wafassessment stays
  vendor-neutral and I/O-free.
- CRS doesn't have rules for every `wafcatalog` family by design (e.g. no
  generic WAF engine inspects cache-key composition) -- some vectors
  (`CACHE-*`) would likely never show a real block against this specific
  engine, which is an honest fact about CRS's scope, not a bug in the
  adapter.
