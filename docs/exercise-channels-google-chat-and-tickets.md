# Exercise channels: Google Chat and tickets

Two exercise step types, added alongside SMTP, SMS, Slack and Teams. Both fail the step with a clear reason when not
configured; neither pretends to send.

## `google_chat`

Posts a text message to a Google Chat space through its incoming webhook.

```json
{ "id": "notify-chat", "type": "google_chat", "config": { "google_chat": { "text": "Drill: please acknowledge." } } }
```

Setup: create an incoming webhook in the space (needs a Google Workspace account that allows incoming webhooks), then set
`GOOGLE_CHAT_WEBHOOK_URL` on the orchestrator. The URL contains a secret token, so handle it like a credential. It is
passed through `packaging/compose/docker-compose.yml` like the Slack and Teams URLs.

Limits, from Google's documentation:
- A message may be at most 32,000 bytes. A longer text fails the step before anything is sent.
- A space accepts about one request per second, shared by every webhook in it. Do not fire several `google_chat` steps
  at the same instant; a 429 fails the step.
- Webhooks are one-way: replies in the space are not seen by the exercise.

## `ticket`

Opens one ticket in a configured ServiceNow or Jira connector (Settings, Integrations). The generic webhook connector
does not support it.

```json
{ "id": "open-ticket", "type": "ticket",
  "config": { "ticket": { "connector_id": "<connector config id>", "subject": "Suspicious login",
                           "body": "User reports unexpected MFA prompts.", "record_type": "incident" } } }
```

- `connector_id` is the id of an enabled connector; `subject` is required (a blank one fails the step).
  `record_type` is optional and defaults to `incident`.
- The ticket is always marked as a drill: the title starts with `[BAS EXERCISE]`, the body ends with a note that it is a
  simulation, and Jira tickets carry the label `BAS-EXERCISE` so the SOC can filter them out of real queues.
- It does not use the finding ticket path, so it carries no ATT&CK technique or host text and is not recorded against a
  finding. The connector's own assignment group (ServiceNow) and project (Jira) still apply.
- The created ticket id and URL are stored in the step result and the evidence chain.

### Cleanup: drill tickets are closed when the exercise ends

When an exercise completes or is aborted, each drill ticket it opened is **closed by default**, so a drill does not
leave open tickets in a real queue. The close note says it was a drill (it never uses the finding path's "technique is
now prevented" text). Set `"keep_open": true` on the ticket step to leave it open, for example if the SOC wants drills kept
as a record.

- It runs once per ticket and is recorded in the evidence chain as `cleanup_done`, `cleanup_skipped` (keep_open) or
  `cleanup_failed`. A failed close never blocks the abort; the ticket stays eligible for a later pass, and you can see
  the failure in the evidence.
- Cleanup runs after the score is computed, so it never changes the score.
- Only tickets can be cleaned up. Chat webhooks and SMS are one-way: they cannot be read back or unsent, so a message
  already sent stays sent.

### `wait_for_ticket`

Waits until a ticket opened by an earlier ticket step is picked up, and records that as the SOC's acknowledgement.

```json
{ "id": "wait-ack", "type": "wait_for_ticket", "timeout_secs": 3600,
  "config": { "wait_for_ticket": { "ticket_step_id": "open-ticket", "until": "acknowledged" } } }
```

- `until` is `acknowledged` (default: the ticket is in progress or resolved) or `resolved`.
- When it fires it records `soc_acknowledged` evidence, which sets `Technical.SOCAcknowledged` and
  `time_to_acknowledge_s` (injected ticket to acknowledgement) in the exercise score.
- Set `timeout_secs`. If nobody acknowledges in time the step completes as timed out and the score records **no**
  acknowledgement; that is a real result, not an error. Without a timeout it waits as long as the exercise runs.
- A step that can never succeed (no such ticket step, `until` not recognised, ticketing that cannot report status) fails
  visibly instead of waiting forever.
- The ticket step is recorded as `ticket_injected` evidence, not `ticket_created`: the score reads `ticket_created` as
  the defenders raising a ticket, and a ticket the exercise opens itself is not that.

### Aborting

Aborting cancels a send that is still in flight for every sending channel (Google Chat, Slack, Teams, SMS, tickets and
email): the request is cancelled and the step is marked cancelled, not failed or completed.

- **SMS and email send to a list.** They stop before the next recipient. What already went out is real, and it is kept in
  the execution's event log as `send_cancelled` with the partial counts; it is not written as a completed send. A message
  being sent at the instant of the abort is reported as `interrupted` (SMS), not as sent or failed, because whether it
  arrived is unknown.
- **Email cannot interrupt a message already in delivery** (Go's SMTP client has no cancellation), so cancellation there
  is per message.
- Running BAS agent steps are not touched by an abort, as before.

Not verified: these have been tested against fake ServiceNow and Jira servers only, never a live instance. A real
instance may need a different record type or required field than the defaults.
