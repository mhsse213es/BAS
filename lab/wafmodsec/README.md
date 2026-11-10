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
- Not wired into any `internal/wafassessment` enterprise scenario or
  `internal/api` handler -- this is the adapter only, proven standalone.
  Wiring a scenario to run live instead of fixture-backed is a separate,
  larger follow-up (it would need every scenario's fixtures to become
  optional-live, not a small change).
- CRS doesn't have rules for every `wafcatalog` family by design (e.g. no
  generic WAF engine inspects cache-key composition) -- some vectors
  (`CACHE-*`) would likely never show a real block against this specific
  engine, which is an honest fact about CRS's scope, not a bug in the
  adapter.
