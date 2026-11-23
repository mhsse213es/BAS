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

Not verified: these have been tested against fake ServiceNow and Jira servers only, never a live instance. A real
instance may need a different record type or required field than the defaults.
