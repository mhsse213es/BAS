# Agent Tray Settings + Troubleshoot Design

## Context

Today, repointing an already-enrolled Windows agent at a new orchestrator
host means hand-editing a registry value
(`HKLM\SYSTEM\CurrentControlSet\Services\BASAgent\Parameters\BAS_SERVER_URL`)
and restarting the service — no UI, no validation, no way to test the new
host before committing to it. Diagnosing a connectivity failure means
manually working through `docs/guides/troubleshooting.md` Section 2:
checking the service state, the configured URL, TCP reachability, and
grep-ing the log file for one of several known error strings.

This builds a "Settings" and "Troubleshoot" item on the existing Windows
agent tray icon so an operator can do both from the tray: change the
server host (with a non-disruptive Test before Save), and run the
existing manual runbook as a live, guided diagnostic instead of a
document to follow by hand.

**Platform scope: Windows only.** The tray icon, its window-spawning
pattern, and the WebView2→windigo migration are all Windows-specific
(`agent/tray_windows.go`, `agent/statuswindow_windows.go`). Linux and
macOS agents are headless services with no GUI surface at all — no tray,
no window toolkit. CLI equivalents (`agent --set-server`, `--test-server`,
`--diagnose`) are a reasonable follow-on for parity but are out of scope
for this spec.

## Why this fits the existing architecture

Three existing facts make this an extension, not a new subsystem:

1. **The tray already runs unprivileged, in the user's session.** The
   SYSTEM service spawns it via `CreateProcessAsUser`
   (`launchTrayForActiveSession`, `agent/usertoken_windows.go:244`, called
   from `agent/service.go:134` and `:160`), and the tray itself already
   spawns further native windows as plain child processes (`exe
   --status-window`, `agent/tray_windows.go:347`) — no further elevation
   dance needed, since it's already in the right session.
2. **WebView2 is gone, windigo is the idiomatic replacement.** Per the
   doc comment at `agent/statuswindow_windows.go:27-32`, WebView2 was
   abandoned because hosting it through the `CreateProcessAsUser`/
   `WTSQueryUserToken` spawn chain left the host window permanently
   invisible (a documented Microsoft bug). `github.com/rodrigocfd/windigo`
   (pure Go, native Win32 window bindings, zero CGo) replaced it and is
   already used for the status console (`newWindigoWindow`,
   `agent/statuswindow_windows.go:250`). Settings and Troubleshoot windows
   are built the same way.
3. **The privileged/unprivileged boundary already has a channel.** The
   SYSTEM process already runs a bearer-token-authed loopback HTTP API at
   `127.0.0.1:9001` (`startLocalAPI`, `agent/local_api_windows.go:36`),
   currently read-only (`/status`, `/activity`, `/evidence`, `/controls`,
   `/logs`, lines 72-76). Writing `BAS_SERVER_URL` requires registry write
   access to `HKLM\SYSTEM\...`, which the unprivileged tray process
   doesn't have — the local API, inside the already-SYSTEM process, is
   where that write has to happen.

## 1. Tray menu

Right-click menu becomes: "Open Status", "Settings...", "Troubleshoot...",
separator, "Export Diagnostic Bundle", "Open Logs Folder". **No Exit
item** — the current menu deliberately has none
(`agent/tray_windows.go:302-306`, with a comment that the client must not
be able to quit the tray from its own menu); nothing about this feature
changes that reasoning, so it stays out.

## 2. Settings window

A windigo window with the current server host pre-filled in a text field,
and two buttons: **Test** and **Save**.

### Test

Non-disruptive: never touches persisted config, never restarts the
service, never affects the live connection. Flow:

1. Read the candidate host from the field.
2. Validate the URL syntactically (scheme, host, port) before any network
   call. A malformed value is reported as **Invalid host** with no
   network attempt.
3. Call a new local-API endpoint, `POST /config/test-server`, running
   inside the already-privileged SYSTEM process (needed because it uses
   the agent's real client certificate, which the unprivileged tray
   process does not have access to).
4. Inside the service process: build a candidate config for the typed
   host via the existing `withServerURL(cfg, serverURL) Config`
   (`agent/bootstrap.go:273`), resolve its real mTLS port via
   `operationalURL(serverURL)` (`agent/bootstrap.go:297`), and attempt an
   actual TLS handshake using the agent's real client certificate against
   that candidate. **A completed handshake alone is not sufficient** — it
   only proves the certificate chain validates, not that the orchestrator
   will accept this agent. Follow the handshake with one real,
   lightweight authenticated call (the existing heartbeat/status check)
   against the candidate host, so an application-layer rejection (e.g.
   the agent is not recognized, or is revoked) is distinguishable from a
   pure TLS failure.
5. Classify the outcome into exactly one of:

   | Result | Cause |
   |---|---|
   | Connected | TLS handshake succeeded and the authenticated call succeeded |
   | Server rejected connection | TLS succeeded, but the authenticated call was rejected |
   | Certificate validation failed | TLS handshake failed on chain validation |
   | Host unreachable | DNS resolution or TCP connect failed |
   | Invalid host | Caught before any network call, at step 2 |

   Show the specific result and the underlying error text, not a generic
   "failed."

### Save

1. Validate the candidate host (same check as Test step 2).
2. Show the exact host being applied and an explicit warning that the
   agent service is about to restart.
3. Call a new local-API endpoint, `POST /config/set-server`. Inside the
   service process: record the current value, persist the new one via
   the existing `writeServiceParams(serverURL, envLabel, enrollPort
   string) error` (`agent/service.go:577` — already used at install time,
   `svcInstall` line 205, and at update, line 320; no new persistence
   mechanism), then restart the service.
4. **Rollback on failure, not a blind success report.** After restart,
   wait up to a bounded timeout for the agent to reconnect (reuse the
   same TLS-handshake-plus-authenticated-call check Test uses, now
   against the configured host). If it doesn't reconnect in time, revert
   `BAS_SERVER_URL` to the recorded previous value, restart again, and
   report the real outcome — "the new host could not be reached; reverted
   to the previous configuration" — never "saved" on the strength of the
   registry write alone.

## 3. Security boundary: the local API's new mutating endpoints

The existing bearer token at `%ProgramData%\BASAgent\api.token` is
readable by any process running as the logged-in user. That's an
acceptable exposure for read-only status today. It is **not** acceptable
for `set-server`: anyone who can read that file could silently repoint
the agent at an attacker-controlled host with no admin rights needed —
a real privilege escalation, not a cosmetic gap.

**Rejected approach:** a per-launch secret passed via command-line
argument or environment variable to the spawned tray process. This fails
against the actual threat model — on Windows, any process running as the
same logged-in user can read another same-user process's command line and
environment block via standard, unprivileged APIs (`OpenProcess` with
`PROCESS_QUERY_LIMITED_INFORMATION`, then reading the PEB). A static file
was never the only leak path; argv and env are exposed the same way, to
the same class of neighbor process.

**Chosen approach:** a named pipe, created with a security descriptor
restricted to the exact logged-in user's SID, used for the two mutating
calls (`test-server`, `set-server`) specifically. The service additionally
checks `GetNamedPipeClientProcessId()` on every connection against the
exact PID it recorded when it spawned the tray process via
`CreateProcessAsUser`. A connection is accepted only from that literal
process — not "any process owned by this user," which the SID-scoped ACL
alone would still allow. This closes both attacks the rejected approach
left open: reading a secret off the tray process, and a neighbor process
connecting directly and pretending to be the tray. The existing read-only
endpoints (`/status`, `/activity`, `/evidence`, `/controls`, `/logs`) are
unaffected and keep using the existing static bearer token — only the two
new mutating endpoints move to the pipe + PID check.

## 4. Troubleshoot window

A windigo window running `docs/guides/troubleshooting.md` Section 2 live,
as six ordered checks, each independently re-runnable:

1. **Agent service.** Query the Windows Service Control Manager. If
   stopped, explain that and offer to start it.
2. **Configured server.** Read the *effective* configuration from the
   service's own loaded config (not the Settings dialog's text field,
   which may be unsaved/stale) — the service already exposes this via the
   local API's `/status` endpoint.
3. **Network and TLS.** The same TLS-handshake-plus-authenticated-call
   check Test uses, against the currently configured host, using the
   agent's real certificate.
4. **System clock.** Compare local time against a trustworthy timestamp
   obtained during the step-3 communication attempt (e.g. the TLS
   handshake or HTTP response timestamp) — no NTP dependency. Flag
   skew that could invalidate time-sensitive authentication (the
   documented >5-minute JWT failure mode in the runbook's Section 2.2)
   only when the evidence actually shows skew; never assume it as the
   default explanation for a failure.
5. **Last connection error.** Add one structured field to the agent's
   status data — classified reason, category, and timestamp of the last
   meaningful connection failure — set at the moment a real connection
   attempt fails, inside the agent's own connection code. This replaces
   fragile log-text grepping (the runbook's current approach) with a
   field the diagnostic window reads directly.
   `agent/statusclient/statusclient.go:104`'s `StatusResponse` already
   carries `ServerConnected`/`LastHeartbeat`/`DisconnectedSec` but nothing
   structured about *why* the last attempt failed — this is the gap this
   step closes.
6. **Proxy and authentication.** Classify the step-5 structured reason
   against the runbook's known categories (proxy auth, DNS, TCP, TLS,
   server-side rejection — the runbook's Section 2.5 log strings:
   `SSPI unavailable`, `no Basic credentials configured`, `no supported
   mechanism`, `proxy rejected the configured credentials`). Only label a
   failure as a proxy issue when the evidence actually supports it.

Each failing check shows: the cause, the evidence behind it, the
recommended next action, and — where one applies — a button ("Test
Connection", "Change Server...", "Open Windows Date & Time Settings").
The existing "Export Diagnostic Bundle" item is unchanged and remains the
fallback for anything the guided checks can't resolve.

## Non-goals

- Linux/macOS UI (headless, no tray surface to extend — CLI parity is a
  separate follow-on).
- Automatically fixing clock skew (an OS-level setting, not the agent's
  to touch) — the diagnostic explains and links to the fix, doesn't apply
  it.
- Changing the read-only local-API endpoints' existing static-token auth
  — only the two new mutating endpoints move to the pipe + PID check.
- A general-purpose settings UI for anything beyond the server host.

## Implementation order

1. Confirm the exact current state of everything this design assumes:
   tray menu code, windigo window pattern, local API auth, config-write
   function, service restart flow, TLS/client-cert logic, troubleshooting
   runbook — all cited above, but re-read at implementation time since
   this spec may lag the code.
2. Settings window + Test (UI, host validation, the non-disruptive
   communication check, the five-way result classification).
3. Save (named-pipe + PID-checked mutating endpoint, persistence via the
   existing `writeServiceParams`, restart, rollback on failed
   reconnection).
4. Troubleshoot window (the six checks, the new structured
   last-connection-error field, guided remediation with action buttons).
5. End-to-end verification: valid and invalid hosts, unreachable server,
   untrusted certificate, application-layer rejection, service restart
   failure and rollback, and an unauthorized local process attempting the
   mutating endpoints directly (must be refused).

## Expected outcome

An operator can change the agent's server host, test it before applying,
and diagnose common connectivity failures entirely from the Windows tray
— without editing the registry or working through a troubleshooting
document by hand.
