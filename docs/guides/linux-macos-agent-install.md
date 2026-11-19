# Installing the agent on Linux and macOS

Both installs work the way the Windows installer does: **one download from the dashboard, one secret to type.**
The server address, ports, deployment CA and the agent itself are inside the download. Nothing is pasted into a
terminal on macOS; on Linux the one command is `sudo ./bas-agent-setup-linux.run`.

Get the download from **Agents → Deploy Agent** (signed in as an administrator).

## Linux (Ubuntu 20.04+, Debian 10+, RHEL/Rocky 8+)

| Download | For |
|---|---|
| Setup file (.run, x86_64) | Intel/AMD 64-bit |
| Setup file (.run, ARM64) | ARM 64-bit (for example AWS Graviton, Raspberry Pi 4/5) |

```
chmod +x bas-agent-setup-linux.run
sudo ./bas-agent-setup-linux.run
```

It asks for the **agent secret** (hidden). If this server issues single-use enrolment tokens it also asks for the
**token** for this host (required, not skippable). Then:

1. The server and the secret are checked first. **A wrong secret, an unreachable server or an untrusted certificate
   stops here and changes nothing**, so a host that already has a working agent keeps it.
2. An agent already installed is replaced; its enrolment is kept when the CA is unchanged.
3. The service `bas-agent` is installed and started.

The secret and the token are never on a command line: the secret is passed on stdin and the token through a
private temporary file the agent deletes after reading it. For scripted installs, give the secret in
`BAS_AGENT_SECRET` and a token with `--token-file <path>` or `--token-stdin`.

Failures are named: *the server rejected the agent secret*, *the server could not be reached*, *the server refused
the enrolment token*, and so on, and a connection problem is never reported as a bad secret or token.

## macOS (12 Monterey or later)

| Download | For |
|---|---|
| Setup app (Apple Silicon) | M1/M2/M3/M4 Macs |
| Setup app (Intel) | Intel Macs |

1. Unzip the download. You get **Audspect Agent Setup**.
2. **Right-click (Control-click) it and choose Open**, once. The build is not Apple-notarized, so a plain
   double-click is blocked by Gatekeeper; *Open* is the one-time approval. (A notarized build removes this step; it
   needs an Apple Developer ID account.)
3. Type the **agent secret** (hidden). On a token-mode server it then asks for the **enrolment token**.
4. Approve the macOS **administrator password** prompt.
5. A message confirms the agent is installed and running; it appears in the dashboard within about a minute.

Behind the scenes the app: refuses a copy built for the other kind of Mac, checks the agent's SHA-256 against the
value the server recorded, checks the server and the secret **before** asking for the administrator password, then
installs the launchd daemon `com.audspect.bas-agent`. If the agent is already installed it says so and changes
nothing. Cancelling any prompt ends quietly. The secret is held in a private temporary file for the length of the
install and passed on stdin; it is never on a command line and the file is removed however the app ends.

## What is verified

* The download comes from the authenticated dashboard. The agent binary is checked against the **signed integrity
  manifest** before it is packed; an agent that is missing, unlisted or altered is **never served**.
* The macOS app carries a freshly **signed `deployment.json`**; the agent verifies it against the signing
  fingerprint stored beside it. You can compare that fingerprint with the one shown in the dashboard.
* Neither download contains the agent secret.

## Honest limits

* **Not yet run on a real Mac or a clean Linux VM.** The scripts are covered by automated tests that run the real
  setup scripts against stand-ins for `osascript` and the agent (secret never on a command line, cancel, wrong
  secret, unreachable server, token mode, wrong CPU, damaged agent, already installed, confirm/cancel/failed removal). The things only a real Mac
  can show — the native dialogs, the administrator prompt, Gatekeeper, launchd — are unverified until someone runs
  it. Run it on one Intel and one Apple Silicon Mac, and one Ubuntu and one ARM64 host, before relying on it.
* macOS is not notarized, so the one-time right-click → Open is required.
* The Linux `.run` still fetches nothing from the network except the server; the macOS app needs no Terminal.

## Uninstalling

Same idea: one download, nothing to type. Both are on **Agents → Deploy Agent**, next to the installers, and the
dashboard's **Uninstall Agent** does the same removal remotely.

| OS | Download | How |
|---|---|---|
| Linux | Uninstaller (.run) | `sudo sh ./bas-agent-uninstall-linux.run` |
| macOS | Uninstaller (both Macs) | unzip, right-click **Audspect Agent Uninstall** → **Open** (once), confirm, approve the administrator prompt |

The agent for the machine's CPU is inside the download and is checked against a recorded hash before it is run, so it
works even when the installed agent is missing or damaged. It removes everything the agent created:

* the service (systemd unit, or the launchd daemon) and the program `/usr/local/bin/bas-agent`;
* the configuration `/etc/bas-agent` (which holds the agent secret) and stored database credentials;
* the client key, certificate and enrolled CA in `/etc/audspect/certs` and any `certs.replaced-*` copies, and
  `/etc/audspect-agent`;
* logs `/var/log/bas-agent`, the event spool `/var/lib/bas-agent`, and the log folder in Temp.

Something an administrator put in `/etc/audspect` is left alone and reported. The server is told the agent was
decommissioned. The result is stated at the end ("...was removed" / "could not be fully removed" with the exit code),
and a failure is never reported as success.

An upgrade through the Linux setup file keeps the agent's enrolment: the installer's replace step runs the uninstall
with `BAS_UNINSTALL_KEEP_DATA=1`, which skips the data removal.

Server-side records (the agent's history and audit entries) stay in the dashboard by design.
