# Injector capabilities: status, cleanup and cancel for exercise channels

Date: 2026-11-23. Status: approach approved by the user ("go with your pick"); this note records the decisions.

## Why

The original OpenAEV exercise vision asked every injector for `Send`, `Cancel`, `Status`, `Evidence` and `Cleanup`.
Only `Send` exists. Three gaps are real:

1. Aborting an exercise marks pending and waiting steps cancelled in the database only. A send already running keeps
   going (the handlers run on a background context) and nothing is undone at the external system.
2. Nothing cleans up. A drill ticket opened in a real ServiceNow or Jira stays open after the exercise ends.
3. Nothing reads status back. The three-tier score has `SOCAcknowledged`, but no code sets it.

## Decisions

- **Capabilities, not a mandatory interface.** Webhook chat channels (Google Chat, and as far as is known Slack and Teams)
  and SMS are one-way: no status, no delete. Forcing five methods on them would mean fake successes. A channel declares
  only the capabilities it has; asking for one it lacks returns "not supported".
- **Cancel is generic, not per channel.** For a send in flight the only real cancel is cancelling its context, so the
  executor keeps a cancel handle per running step and `AbortExecution` calls them, and also marks running steps
  cancelled. For something already sent, "cancel" is cleanup.
- **Evidence stays in the executor.** The executor already records evidence for every step; no per-injector method.
- **Cleanup closes drill tickets by default** (user's pick). A ticket step has `keep_open` to leave it. Cleanup runs
  when an exercise ends or is aborted, once per step (idempotent), and records evidence either way. A failed cleanup is
  recorded and reported, never silently dropped.
- **Cleanup must not lie in the ticket.** Today's connector `CloseTicket` writes "BAS revalidation confirmed this technique
  is now prevented", which is wrong for a drill. Exercise cleanup closes with its own note.
- **Status feeds the score.** A new `wait_for_ticket` step waits until a ticket reaches `in_progress` (acknowledged) or
  `resolved`, and records `soc_acknowledged`, which sets `Technical.SOCAcknowledged`.
- **Evidence type naming.** The ticket the exercise injects is `ticket_injected`. `ticket_created` is reserved for
  defender-raised tickets (a bug fixed in 27e21ee1 where the two were conflated).

## Not in scope

Deleting or recalling chat messages and SMS (no API), email recall, the Microsoft 365, WhatsApp and voice channels.

## Not verified

Everything is tested against fake servers. A live ServiceNow or Jira may use different close states or required fields.
