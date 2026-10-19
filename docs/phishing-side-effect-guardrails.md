# Phishing side-effect scenarios: guardrail design

Status: **design only.** Nothing here registers, enables, or executes a scenario.
Approved direction (approver, round 2): side-effecting scenarios run only through
scenario-specific authorization and explicit opt-in. Target scope is bounded, actions
are auditable, cleanup outcomes are visible, and high-impact actions need explicit
target confirmation plus an authoritative postcondition check.

## Scope

| Scenario | Side effect | Who it reaches | Current state |
|---|---|---|---|
| PH-CHN-001 Teams lure | Real webhook message into a Teams channel | Channel members | Adapter-tested; not registered |
| PH-CHN-002 Cloud-sharing invitation | Creates a real sharing invitation; a delete path exists | Named recipient | Adapter-tested; not registered |
| PH-CHN-006 SMS chain | Sends a real SMS | Phone number owner | Adapter-tested; not registered |
| PH-CHN-008 Messaging impersonation | Real Slack webhook message | Channel members | Adapter-tested; not registered |
| PH-IR-002 Identity containment | Revokes all sign-in sessions for a user | The user, immediately | Adapter-tested; not registered |

PH-CHN-004 (calendar event) is handled separately: it is unregistered and kept for its
own review. PH-IR-001 mailbox purge and PH-CHN-007 voice are out of scope.

## Common guardrails (every side-effecting scenario)

1. **Scenario-specific authorization.** Each scenario needs its own grant in the
   installation configuration. A general "phishing enabled" setting is not enough.
   Without the grant the scenario is unavailable, whatever is wired.
2. **Explicit opt-in per run.** The trigger must carry an explicit confirmation field
   naming the scenario and the target set. Omitting it refuses the run before any call.
3. **Bounded target scope.** Targets come only from an install-wide allowlist (the
   same fail-closed pattern as the identity allowlists). A run selects from it and
   never widens it. Empty, wildcard, or out-of-scope targets refuse the whole request,
   with zero outbound calls.
4. **Rate and count bounds.** A maximum number of side effects per run and per day,
   set in configuration. Exceeding it refuses, rather than truncating.
5. **Auditable action record.** Each outbound action is written to `audit_logs` before
   the call (intent) and updated after (outcome), with the run ID, scenario ID, target
   digest, and vendor reference. Targets are hashed where the allowlist does not
   require them in clear.
6. **Visible cleanup outcome.** Every created artifact has a cleanup step, and the
   result reports cleanup separately: removed, not removed, or not supported. A run is
   never reported clean when cleanup was not verified.
7. **Delivery is not a verdict.** Delivery, detection, blocking, and response stay
   separate outcomes, as already established for the other scenarios.

## Per-scenario requirements

**PH-CHN-001 / PH-CHN-008 (chat webhook messages).** Real messages reach real people.
- Confirmation: channel named in the allowlist, plus a message-content review step.
- Cleanup: a webhook message cannot be recalled through the webhook. Report
  "not supported" honestly, unless a delete permission is separately reviewed.
- Postcondition: delivery only (the webhook's own acceptance). No claim that people
  saw it.

**PH-CHN-002 (sharing invitation).** Real recipient, real external email.
- Confirmation: recipient on the allowlist, and the sharing scope declared.
- Cleanup: the invite delete path exists. Verify the invite is gone, and report
  separately if the recipient already accepted it.
- Postcondition: creation verified by reading the invite back. Never proof of
  recipient action.

**PH-CHN-006 (SMS).** Real SMS, carrier cost, and a real person.
- Confirmation: phone number allowlisted and marked as consenting to test messages.
  This is the strictest recipient rule, since SMS has no cleanup.
- Cleanup: not supported. Report it as a permanent side effect.
- Postcondition: provider acceptance only.
- Note: the chain composition (email to SMS) is deferred, so only the SMS leg is in
  scope.

**PH-IR-002 (identity containment). Highest impact.** Revokes sessions and forces
re-authentication for a real user.
- Confirmation: explicit target confirmation from the operator, naming the user
  principal. This is a second confirmation on top of the allowlist, and it needs a
  reason and a ticket reference.
- Scope: one user per run. No bulk revocation.
- Postcondition: must be read back from the server. The verification signal is
  `signInSessionsValidFromDateTime` advancing. **This depends on the same `$select`
  permission that PH-ID-005 has not verified.** PH-IR-002 must not be registered until
  that permission is confirmed.
- Limitation to report: access tokens already held by clients can stay valid until
  they expire. The verdict must say containment was requested and the marker advanced.
  It must not say every token became unusable.
- Cleanup: none possible. Users re-authenticate normally afterward. Record that.

## Open decisions for the approver

1. Whether the per-run confirmation for PH-IR-002 should also require a second
   operator, not only the same operator confirming twice.
2. Whether PH-CHN-006 should be limited to a test phone list that is never a real
   employee's number.
3. Whether a webhook delete permission should be reviewed for PH-CHN-001/008 or the
   "not supported" cleanup result accepted as final.

## Gates before any of these can be registered

- Authorization config keys defined and validated (installer and orchestrator), with
  tests.
- Per-run confirmation field in the trigger, with a refusal test for omission.
- Audit intent and outcome rows, with tests.
- PH-IR-002: the `$select` permission verified in the test tenant.
- Live validation in a test tenant for each scenario, recorded separately.
