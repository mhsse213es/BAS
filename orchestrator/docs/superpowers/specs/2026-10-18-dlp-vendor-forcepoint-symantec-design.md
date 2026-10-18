# Forcepoint DLP + Symantec DLP Vendor Connectors — Design Spec

## Intent

`dlp.txt` §5 names 4 enterprise DLP products Audspect must prove effectiveness against: Microsoft Purview, Forcepoint, Symantec DLP, Trellix. Purview (`internal/vendors/purview`) and Trellix (`internal/vendors/trellixdlp`) are already built, each an evidence client that queries the vendor's own incident/event API and normalizes the result — never a policy-evaluation engine, never a live-tenant-verified claim. This closes the remaining 2: `internal/vendors/forcepointdlp` and `internal/vendors/symantecdlp`, following the identical architecture and the identical "best-effort against documented shape, UNVERIFIED against a live tenant" disclaimer `trellixdlp`'s own package doc comment already carries.

## Why now

§5's own acceptance line: "This is a candidate integration catalogue, not a claim that every named product offers every DLP capability or that an integration has already been implemented." Building these 2 incrementally, named honestly, is exactly what that line licenses — same posture as Purview/Trellix, not a new standard.

## Research (WebSearch, 2026-10-18)

**Forcepoint DLP** (help.forcepoint.com/dlp/10/restapi/, help.forcepoint.com/dlp/90/getting_started/ — versioned docs for DLP 9.0/10, REST API guide PDF pages dated Dec 2021/Mar 2022, feature introduced v8.9):
- Auth: requires a local **Application**-type administrator account in Forcepoint Security Manager (Network accounts cannot be Application type). Two-step token exchange: `POST /dlp/rest/v1/auth/refresh-token` (credentials → refresh token) then `POST /dlp/rest/v1/auth/access-token` (refresh token → access token/JWT), both against the DLP Manager host:port. The access token is sent in request headers for subsequent calls.
- Incidents: `POST /dlp/rest/v1/incidents`. Body is either an ID list or a filters request (mutually exclusive, not both). Max 10,000 incidents per response. Each call returns exactly one type: `INCIDENTS` or `DISCOVERY`. Filters include policy, department, risk level.
- **Confirmed:** endpoint paths, two-step token exchange, mutually-exclusive request shape, 10,000-row cap, INCIDENTS/DISCOVERY type split.
- **NOT confirmed:** exact JSON field names in the incident response body (no field-level schema reference found, only endpoint/parameter documentation); whether the refresh-token/access-token pair behaves like a short-lived-vs-long-lived pair worth caching the way Trellix's token is cached, or whether DLP Manager issues a fresh access token every call; the exact date-range filter parameter name for "incidents between X and Y" (the filters object's shape beyond policy/department/risk-level was not confirmed).

**Symantec DLP (Broadcom)** (security.com product-insights pages, Broadcom knowledge base articles 159948/435102, Cortex XSOAR `symantec-data-loss-prevention-v2` integration docs):
- REST API introduced in DLP 15.7; the older SOAP-style "Incident Reporting and Update API" is a separate web service available from DLP 16+.
- Auth: **Forms-based authentication** with a service-account username/password against the Enforce server (not OAuth) — the XSOAR integration's own config fields are exactly `Enforce server URL` + `username` + `password`. A Broadcom KB article warns the service account can lock after repeated failed logins (default max 6 attempts, default 60-minute lockout).
- Incident listing: filterable by earliest time, status, severity, incident type; paginated, default page size 50.
- **Confirmed:** forms-based username/password auth (not OAuth), filter fields (time/status/severity/type), default page size 50, lockout risk on repeated auth failures.
- **NOT confirmed:** the exact login endpoint path, the exact session-token/cookie mechanics after a successful forms login, the exact incident-list endpoint path and JSON field names, and whether the 15.7 REST API or the 16+ Incident Reporting API is the one a real current license maps to (both exist, this spec cannot determine which a given account uses).

**Implication for this spec:** Forcepoint's auth/request shape is well-confirmed but its response schema is not; Symantec's auth *mechanism* is confirmed (forms-based, not OAuth) but its exact endpoints and response schema are not, and which of 2 API generations applies is unknown. Both clients are therefore best-effort implementations of the documented general pattern, exactly like `trellixdlp`, and must say so in their own package doc comments — never silently presented as verified.

## Goals

1. `internal/vendors/forcepointdlp`: `Config`/`Client`/`New`/a 2-step token exchange (refresh-token → access-token, cached) matching the confirmed auth flow, `QueryDLPIncidents(ctx, start, end) ([]Incident, error)` against `POST /dlp/rest/v1/incidents` with a filters-mode request body, `TestConnection`.
2. `internal/vendors/symantecdlp`: `Config`/`Client`/`New`/a forms-based login exchange (username+password → session credential, cached) matching the confirmed auth mechanism, `QueryDLPIncidents(ctx, start, end) ([]Incident, error)` against a best-effort incident-list endpoint with time/status/severity filters, `TestConnection`.
3. Both package doc comments carry the same explicit unverified-schema/unverified-endpoint disclaimer style as `trellixdlp`'s, naming exactly what's confirmed vs. not (from the Research section above) and pointing at `docs/dlp-mastery-qa-log.md`.
4. A `docs/dlp-mastery-qa-log.md` entry per vendor (items 4 and 5), matching items 1/2's structure (Status/What's needed/What's still unverified/What this means/Resolution path).

## Non-goals

- No policy-configuration-discovery API (§5's "Policy/configuration discovery capabilities" requirement) for either vendor — only the incident/event-retrieval half, matching Purview/Trellix's own current scope (Purview's `QueryDLPEvents` and Trellix's `QueryDLPIncidents` are both event-retrieval only; neither queries policy config today either).
- No live-tenant verification for either vendor — no account/license exists for either product in this environment, same as Purview/Trellix.
- No wiring into `internal/dlpcorrelate`, `internal/reporting/dlp.go`, or any scenario/campaign — these are standalone evidence clients, exactly like Purview/Trellix are today (neither is wired into the live DLP-ENF pipeline; both exist as independently-testable packages pending real tenant access).
- No Forcepoint `Update Incidents` (status/severity/assignment-change) or Symantec incident-update capability — read-only evidence retrieval only, matching §5's phrasing ("Event retrieval, alert correlation and evidence APIs" is the half being closed; write-back is out of scope for this slice).

## Anti-goals

- Must not claim a confirmed response schema where research found none — `Incident` field names for both packages are explicitly flagged best-effort, never presented as "the" Forcepoint/Symantec schema.
- Must not silently pick one of Symantec's two API generations (15.7 REST vs. 16+ Incident Reporting) as "the" implementation without saying so in the doc comment — name both, name the ambiguity.
- Must not duplicate `trellixdlp`'s or `purview`'s own token-caching code via copy-paste beyond what each vendor's own distinct auth mechanics require (Forcepoint's 2-step refresh/access exchange, Symantec's forms-login, Purview's Entra client-credentials, Trellix's Basic-auth client-credentials are 4 genuinely different auth mechanisms — each package owns its own token code, by the same precedent `trellixdlp`'s own doc comment states for why it doesn't reuse `internal/platform/msauth.EntraTokenSource`).

## What's left to the builder

- Exact Go error-wrapping message text (follow `trellixdlp`'s style: `fmt.Errorf("forcepointdlp query incidents: %w", err)`).
- Exact mock-server test shapes (follow `trellixdlp/client_test.go`'s pattern: token mock + incidents-endpoint mock via `httptest`, one test per confirmed behavior, Review Focus comments for the auth-mechanism-specific details).
- Field names inside the `Incident` struct beyond what's spec'd in Goals — reasonable best-effort names consistent with the vendor's documented filter vocabulary (e.g. Forcepoint's `policy`/`department`/`riskLevel` filters imply corresponding incident fields; Symantec's `status`/`severity`/`incidentType` filters imply the same).
