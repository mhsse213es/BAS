# Agent tray Settings and Troubleshoot: manual verification checklist (Task 8)

Plan: `docs/superpowers/plans/2026-10-18-agent-tray-settings-troubleshoot.md`, Task 8.
Spec: `docs/superpowers/specs/2026-10-18-agent-tray-settings-troubleshoot-design.md`.

**What this is.** The Settings and Troubleshoot windows drive Windows-service behaviour (registry, a named pipe,
the SCM, `CreateProcessAsUser`, native windows) that the automated tests cannot exercise. These steps are for a
person on a real Windows install, against a real server.

**How the expected results were written.** They are read from the code (`agent/hostcheck.go`,
`agent/configmutate_windows.go`, `agent/localmutate_windows.go`, `agent/settingswindow_windows.go`,
`agent/troubleshootwindow_windows.go`), **not observed on a running agent**. Where a step disagrees with what you
see, record what you saw: that is a finding, not a failed checklist. Section 9 lists three problems found while
writing this checklist and since fixed in the code; confirm the fixes on your build.

## 0. Before you start

- A Windows machine with the agent installed and **connected** (the status window says Active), signed in as an
  ordinary interactive user. Note its server address: `reg query "HKLM\SYSTEM\CurrentControlSet\Services\Audspect Agent\Parameters" /v BAS_SERVER_URL`.
- Write that value down as `ORIGINAL`. Every scenario ends by restoring it.
- Log file (readable by every user): `C:\Program Files\Audspect\agent.log`. Keep it open; entries are quoted below.
- Service name is `Audspect Agent`. Windows may need an elevated prompt for `sc` and `reg query`.
- Open the tray menu (right-click the Audspect icon). Expected items, in order: **Open Status Console**,
  **Settings...**, **Troubleshoot...**, a separator, **Export Diagnostic Bundle**, **Open Logs Folder**. There is
  deliberately no Exit item.
- Windows can be launched by hand for repeat runs: `bas_agent.exe --settings-window` and
  `bas_agent.exe --troubleshoot-window`. **Do this from the tray for the scenarios below**; a hand-launched window has
  the wrong parent and is refused by design (scenario 7).

Result key used below: **Test** shows `<Outcome>: <detail>` in the result area, where `<Outcome>` is one of
**Connected**, **Server rejected connection**, **Certificate validation failed**, **Host unreachable**,
**Invalid host**. A successful test shows just `Connected`. No internal code (`cert_invalid` and the like) should ever
appear on screen.

## 1. Settings opens and shows the current host

1. Tray > **Settings...**
2. Expect a window titled **Audspect BAS Agent — Settings** with the host box pre-filled with `ORIGINAL`, and
   **Test** and **Save** buttons.

## 2. Test: valid host -> connected

1. Leave the host as `ORIGINAL` and click **Test**. The result area shows `Testing...` and the window stays
   responsive (the call runs off the UI thread).
2. Expect `Connected`.
3. Expect nothing to change: status window still Active, registry value still `ORIGINAL`, no restart.

## 3. Test: invalid host -> no network call

1. Enter `not a url` and click **Test**. Expect `Invalid host: missing scheme or host`, immediately.
2. Enter `https://server:9443/api` (has a path). Expect `Invalid host: must not include a path, query, or fragment`.
3. Confirm with a packet capture or the server's access log that **neither** attempt reached the network: the host
   is validated before the pipe is used.

## 4. Test: the four failure outcomes (the part most likely to be wrong)

A completed TLS handshake alone must **never** read as connected: only a handshake **and** an authenticated call
that succeeds is `connected`.

| Scenario | How to set it up | Expected |
|---|---|---|
| Host unreachable | Enter `https://192.0.2.1:9443` (a documentation address) or a closed port on a live host | `Host unreachable: ...` with the dial error |
| Certificate invalid | Point at any HTTPS service on a listening port that is **not** signed by the deployment CA (for example `https://localhost:<port>` of a throwaway server) | `Certificate validation failed: ...` naming the certificate problem |
| Server rejected | A host that completes TLS with a certificate from the deployment CA and answers the authenticated heartbeat with a 4xx/5xx. With one server this is easiest by temporarily revoking or force-removing this agent in the console and testing `ORIGINAL` | `Server rejected connection: server <code> on /api/heartbeat` (record the code you actually get; the revoked-agent case may fail at TLS instead and read `Certificate validation failed`) |
| Listening port, no TLS | Any plain-HTTP service | `Host unreachable` or `Certificate validation failed` with the TLS error. Record which |

Restore anything you revoked before continuing.

## 5. Save: success

1. Use a second reachable server you control, or `ORIGINAL` written differently (for example the DNS name instead of
   the IP), so the change is real but still works.
2. Click **Save**. Expect: "Saving switches this agent to the new server. It reconnects without restarting, which
   may briefly interrupt connectivity; if it cannot reach the new server within 30 seconds, the previous server is
   restored. Continue? (click Save again to confirm)". Nothing has been saved yet: re-read the registry value, it
   must still be `ORIGINAL`.
   **Edit-after-warning check:** change the host text now and click **Save**. Expect the same warning again (for the
   new text), and still nothing saved. Only a second click on unchanged text saves. Put the intended host back before
   confirming.
3. Click **Save** again. Expect `Saving...`, then `Saved: Saved and reconnected` within about 30 seconds.
4. Check: the registry value now holds exactly the text you entered; `agent.log` has
   `server host changed via Settings: <host>`; the status window reconnects.
5. **Restart the service** (`sc stop "Audspect Agent"` then `sc start "Audspect Agent"`) and confirm the agent comes
   back on the **new** host (this proves it was persisted, not only applied in memory).

## 6. Save: failure rolls back (restart-failure / unreachable new host)

1. In Settings enter an unreachable host such as `https://192.0.2.1:9443` and **Save**, then confirm.
2. The save waits up to about 30 seconds. Expect `Not saved: could not reconnect within the timeout, reverted to the previous host`.
3. Check: the registry value is back to what it was before the attempt; the agent is connected to the **previous**
   host; `agent.log` shows the change and the revert. The window must never say `Saved` here.
4. Also try Save on a host that fails `Test` (a certificate problem). Expect `Not saved` and the previous host kept.
5. If you can, make the registry write fail (deny SYSTEM write to the `Parameters` key) and Save. Expect
   `Not saved: failed to save the new host: ...` and the live connection untouched. **Undo the permission change.**

## 7. Unauthorised local process cannot use the pipe

The two mutating calls travel over `\\.\pipe\BASAgentMutate`, scoped to the signed-in user and to the SYSTEM service.
The service additionally accepts a connection only if the **connecting process's parent is the tray process it
spawned** and the connecting process's image path equals the service's own executable. Anything else is closed
without a reply.

1. **A copy of the agent started by hand.** From a normal PowerShell prompt run the installed
   `bas_agent.exe --settings-window` (path from `sc qc "Audspect Agent"`). The window opens, but click **Test**
   with a valid host: expect `Host unreachable: The Audspect Agent service on this computer did not answer, so the
   server was not tested...`. Its parent is the shell, not the tray.
2. **A script connecting directly.** In PowerShell:
   ```
   $p = New-Object System.IO.Pipes.NamedPipeClientStream('.','BASAgentMutate',[System.IO.Pipes.PipeDirection]::InOut)
   $p.Connect(3000)
   $w = New-Object System.IO.StreamWriter($p); $w.Write('{"op":"set-server","host":"https://192.0.2.1:9443"}'); $w.Flush()
   $r = New-Object System.IO.StreamReader($p); '[' + $r.ReadToEnd() + ']'
   ```
   Expect an empty reply `[]` (the connection is closed) and **no change** to the registry value or the live host.
   Connection refused or access denied from a different user account is also a pass.
3. Confirm the read-only local API (`http://127.0.0.1:9001/status`, bearer token in
   `C:\ProgramData\BASAgent\api.token`) still works, and that it has **no** `/config/...` routes.

## 8. Troubleshoot window

Tray > **Troubleshoot...** opens **Audspect BAS Agent — Troubleshoot** with six checks. Each can be re-run with its
own **Retry**; **Export Diagnostic Bundle** stays in the tray menu as the fallback.

| # | Check | Healthy result | Break it by | Expected failing result |
|---|---|---|---|---|
| 1 | Service running | pass | `sc stop "Audspect Agent"` | fail: "The Audspect BAS Agent service is not running." with a **Start Service** button |
| 2 | Configured server | pass, shows the live server URL | stop the service | fail: "could not read the agent's local status API: ..." |
| 3 | Connection test | pass with `Connected` | block the server in the firewall (Settings will not save an unreachable host, so break the network instead) | fail with the same cause text as Test, and a **Change Server...** button |
| 4 | Clock skew | pass, shows `Measured skew: <n>s` | set the machine clock more than 5 minutes off (disable time sync first) | fail: "differs from the server's by more than 5 minutes, which breaks JWT validation" with **Open Windows Date & Time Settings** |
| 5 | Last connection error | pass: "No recorded connection failures." | cause a real failure, for example block the server in the firewall for a minute | a recorded failure with `Category: <dns|tcp|tls|proxy_auth|server_rejected|unknown>, at <time>` |
| 6 | Likely cause | "No failure to categorize." | same as 5 | one cause sentence per category (proxy authentication, DNS, network level, certificate, rejected requests) |

Things to confirm specifically:

- **Check 3 is always a live call.** After a successful Settings Test, break connectivity and re-run check 3: it must
  fail, not repeat the earlier success.
- **Check 4 only flags skew with evidence.** With the clock correct it must say pass. It reads the server's own time
  from check 3's response, so with check 3 failing it should read as pending ("could not measure -- the connection
  test did not return a server timestamp") or as an error. Record which; it must not read as a pass.
- **A proxy is named only on evidence.** Check 6 may say "Proxy authentication is likely blocking..." only when the
  recorded error contains one of: `SSPI unavailable`, `no Basic credentials configured`, `no supported mechanism`,
  `proxy rejected the configured credentials`. A plain timeout must not be labelled a proxy problem.
- **Check 2 shows the running config, not what is typed in Settings.** Change the Settings box without saving, open
  Troubleshoot, and confirm check 2 still shows the real host.
- Start the service again and **Retry** each check; all six should return to pass.

## 9. Problems found while writing this checklist (now fixed in the code: confirm on your build)

1. **The Save warning used to say the service would restart. It does not restart.** Save writes the registry and
   hot-swaps the running process's configuration, because restarting the service from inside itself would kill the
   code that verifies and rolls back. The warning now says the agent reconnects without restarting and that the
   previous server is restored if the new one is not reachable within 30 seconds. (Step 5.2.)
2. **Test results used to show raw outcome codes** (`cert_invalid: ...`). They now show the five plain-language names
   from the design. (Sections 2 to 4.)
3. **Editing the host after the Save warning.** This was first written up wrongly as "the edited host is saved without
   a fresh warning". It was not: the old text was refused, but the message said "click Save again" and that click only
   showed the warning again, so it took two extra clicks. The confirmation now follows the text on screen: an edit
   gives a fresh warning for the new host on the next click, and a save always needs a click on unchanged text.
   (Step 5.2, "Edit-after-warning check".)

## 10. Recording the result

For each section write: PASS, FAIL or DIFFERENT, with the exact text shown and the matching `agent.log` lines. Return
the filled-in list so the findings can be fixed; nothing here has been run by the author.
