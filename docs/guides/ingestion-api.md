# Generic Inbound Security Event Ingestion API

This endpoint lets your own SIEM, SOAR, or ITSM tooling push detection and
evidence records into Audspect without a bespoke, vendor-specific
connector. It is the inverse of Audspect's Detection Validation connectors
(which pull alerts from a handful of named vendors during a BAS run):
here, your tooling pushes to Audspect instead.

**Scope note:** this is a single-tenant, on-prem endpoint — one Audspect
deployment per customer. There is no multi-tenant key management; one
shared secret authenticates every request to this deployment.

## Enabling it

The endpoint is **disabled by default**. Set `BAS_INGEST_API_KEY` to a
long, random secret in your deployment's environment to enable it — an
unset key means the endpoint returns `404 Not Found`, not an open door.

```bash
BAS_INGEST_API_KEY=$(openssl rand -hex 32)
```

If your Audspect server is reachable from the internet (not every
deployment is air-gapped), treat this key with the same care as your
database password: rotate it if it may have leaked, and restrict which
source IPs can reach `/api/ingest/v1/events` at your firewall or reverse
proxy if possible.

## Endpoint

```
POST /api/ingest/v1/events
Authorization: Bearer <BAS_INGEST_API_KEY>
Content-Type: application/json
```

### Request body

```json
{
  "schema_version": 1,
  "events": [
    {
      "source": "splunk",
      "external_event_id": "evt-20261007-0001",
      "event_type": "detection",
      "timestamp": "2026-10-07T09:30:00Z",
      "severity": "high",
      "technique_id": "T1059.001",
      "ioc": { "type": "ip", "value": "203.0.113.9" },
      "raw": { "rule_title": "Suspicious PowerShell", "host": "WORKSTATION-12" }
    }
  ]
}
```

| Field | Required | Notes |
|---|---|---|
| `schema_version` | yes | Must be `1`. Reserved for future breaking changes to this shape. |
| `events[].source` | yes | Free text identifying your tool, e.g. `"splunk"`, `"sentinel"`, `"your_soar"`. Not validated against a fixed vendor list — this is the generic path, not a named connector. |
| `events[].external_event_id` | yes | Your own event/alert ID. Combined with `source`, this is the idempotency key — see below. |
| `events[].event_type` | no | Free text, e.g. `"detection"` or `"evidence"`. Not enforced; carried through into the IOC's metadata for your own later filtering. |
| `events[].timestamp` | no | RFC 3339. Not currently validated or used in matching — reserved for future windowed correlation. |
| `events[].severity` | no | Free text, carried through into metadata. |
| `events[].technique_id` | no | An ATT&CK technique ID, if known. Carried through into metadata; not currently cross-referenced against a running BAS step (see "What this does not do" below). |
| `events[].ioc` | no | `{type, value}`. `type` must be one of the indicator types Audspect already uses internally (`ip`, `domain`, `url`, `file_hash`, `filename`, `registry_key`, `mutex`, `service`, `process`, `command_line`, `ja3`, `user_agent`, `email`, `dns_record`, `certificate`). An event with no `ioc` is still recorded (see idempotency below) but produces no indicator row — useful for a pure "we saw nothing" evidence record. |
| `events[].raw` | no | Arbitrary JSON, carried through into the stored IOC's metadata for audit/evidence purposes. Not interpreted. |

### Response

`200 OK` with one result per submitted event, in the same order:

```json
{
  "results": [
    { "external_event_id": "evt-20261007-0001", "status": "created", "ioc_id": "a1b2c3..." }
  ]
}
```

| `status` | Meaning |
|---|---|
| `created` | A new event was recorded. `ioc_id` is set if the event carried an `ioc` payload. |
| `duplicate` | This exact `(source, external_event_id)` was already ingested — safe, not an error. Retry freely. |
| `error` | The event itself was rejected (see `error` field for why — missing `external_event_id`, unknown `ioc.type`, etc.). Nothing was recorded for this one event; the rest of the batch is unaffected. |

### Error codes (whole-request failures)

| Code | Meaning |
|---|---|
| `404` | The endpoint is disabled (`BAS_INGEST_API_KEY` not set). |
| `401` | Missing or incorrect `Authorization: Bearer` key. |
| `400` | Malformed JSON, or `schema_version` is missing/unsupported. |
| `500` | An unexpected database failure partway through the batch. Already-recorded events in that batch are unaffected (idempotency protects a retry — see below) — resubmit the whole batch. |

An individual event's own validation problem is **never** a whole-request
error; it comes back as `"status": "error"` in that event's own result
(see the table above), so one bad event never forces you to resend the
rest of a batch.

## Idempotency and retries

`(source, external_event_id)` is the idempotency key. If your tool's
delivery can retry (at-least-once delivery, a timeout you treat as
"unknown, try again"), just resend the same batch — every event that was
already recorded comes back `"status": "duplicate"` instead of being
recorded twice or double-counted.

## What this does into Audspect

Every event with an `ioc` payload is written into Audspect's existing
indicator registry — the same place IOCs from your own BAS runs, manual
imports, and threat-feed ingestion land — tagged as
`source = customer_detection`, `origin = customer`. It does **not** create
a new, Audspect-specific schema you need to match; map your own alert
format into the generic `{type, value}` shape above and the rest is
handled for you.

## What this does *not* do (yet)

- **It does not correlate against a running BAS exercise.** Pushing a
  detection event here records an indicator; it does not mark a specific
  technique as "detected" for a specific run the way Audspect's own
  Detection Validation connectors do when they pull from a named vendor
  (Elastic, Splunk, QRadar, Sentinel, Defender XDR, CrowdStrike, Trellix)
  during an active exercise window. If you want push-based detection
  verification tied to a specific run, that is a larger feature than this
  endpoint and isn't built yet.
- **No mTLS option.** Authentication is the single bearer key described
  above. If your environment requires mutual TLS for inbound integrations,
  say so — it can be added, but no customer has asked for it yet.
- **No per-event replay-protection window beyond the idempotency table
  itself.** There's no timestamp+nonce signature scheme; TLS transport
  security plus the bearer key is the current threat model. If your
  deployment is internet-facing and this isn't enough, ask — this is a
  deliberate v1 scope cut, not an oversight.

## Example: a generic `curl` integration

```bash
curl -s -X POST https://your-audspect-host/api/ingest/v1/events \
  -H "Authorization: Bearer $BAS_INGEST_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "schema_version": 1,
    "events": [
      {
        "source": "my_siem",
        "external_event_id": "my-siem-alert-4471",
        "event_type": "detection",
        "ioc": {"type": "command_line", "value": "powershell -enc ..."}
      }
    ]
  }'
```

Point your SIEM/SOAR's outbound webhook/alert-action feature at this URL
with this body shape. Vendor-specific examples (Splunk alert actions,
Sentinel playbooks, QRadar custom actions, ServiceNow outbound REST) can
sit on top of this generic shape later if a customer needs one — they
are not required to use the API.
