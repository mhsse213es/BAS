# PH-IR-003: EDR request shapes, comparison with vendor documentation

Status: **partially confirmed. Not live-validated.** Written as a review record. It
changes no code and enables nothing.

## What PH-IR-003 actually reads

PH-IR-003 does not call a vendor. `executePHIR003` loads the most recent
`action_requests` row for the given run ID, through `phishbridge.FromEPPResponseAction`.
The vendor request is made by the EPP response-action connectors. The shapes below
are what those connectors send.

## Implementation (as sent)

| Vendor | Action | Method and path | Query | Body |
|---|---|---|---|---|
| CrowdStrike | Isolate ("contain") | POST `/devices/entities/devices-actions/v2` | `action_name=contain` | `{"ids":["<deviceID>"]}` |
| CrowdStrike | Release ("lift_containment") | same | `action_name=lift_containment` | same |
| SentinelOne | Isolate ("disconnect") | POST `/web/api/v2.1/agents/actions/disconnect` | none | `{"filter":{"ids":["<deviceID>"]}}` |
| SentinelOne | Release ("connect") | POST `/web/api/v2.1/agents/actions/connect` | none | `{"filter":{"ids":["<deviceID>"]}}` |

Source: `internal/vendors/crowdstrike/client.go` (`deviceAction`) and
`internal/vendors/sentinelone/actions.go` (`agentAction`).

## Comparison with public documentation

- **CrowdStrike.** Third-party integration docs confirm the devices-actions v2 path,
  the `contain` and `lift_containment` action names, and a limit of 100 host IDs per
  call. They do not show the exact placement of `action_name` (query or body) or the
  `ids` field. The official Falcon API reference (Hosts, devices-actions v2) was not
  retrieved, so the placement stays **unconfirmed**.
- **SentinelOne.** Third-party docs describe action endpoints as taking a `filter`
  object and a data object, which fits `filter.ids`. The official management API
  reference for `agents/actions/disconnect` was not retrieved, so the body shape
  stays **unconfirmed**.

## Mismatches and gaps

1. No mismatch was found in the third-party sources. Neither source contradicts the
   implementation. The gap is that the authoritative references were not checked.
2. The CrowdStrike connector returns the vendor trace ID. The SentinelOne connector
   returns the device ID instead, because the response carries no action ID. That
   weakens the audit trail for SentinelOne releases and should be reviewed separately.
3. PH-IR-003's verdict depends only on the stored `action_requests` row, not on the
   vendor's own confirmation of containment. The scenario must not be read as proof
   that the device was isolated.

## Not done (needs access or a test tenant)

- Read the official CrowdStrike Falcon API reference for devices-actions v2 and
  confirm the `action_name` placement and body.
- Read the official SentinelOne management API reference for
  `agents/actions/disconnect` and confirm the `filter.ids` body.
- Live call against a test tenant. Until then PH-IR-003 is not live-validated.
