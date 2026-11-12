# Download Stager: inspection and cleanup status

Family: `T1059.001` / `Download Stager` (seeded in `orchestrator/internal/db/postgres.go`), risk MODERATE, executor powershell.

Payload, verbatim from the seed:

    $wc=New-Object Net.WebClient;try{$wc.DownloadString('http://127.0.0.1/bas-test')}catch{"Connection refused - expected"}

## What it does

| Area | Effect |
|---|---|
| Files | None. The downloaded string is discarded, never written. |
| Registry | None. |
| Services, scheduled tasks, startup entries | None. |
| Processes | None. A WebClient object is created in memory and released. |
| Network | One outbound request to `127.0.0.1:80/bas-test`, loopback only. Nothing listens there by default, so it fails as the payload expects. |
| Memory | Only the in-process WebClient. |

Result: the base payload creates no artifact that needs reverting.

## Variant wrappers

Every variant wraps this payload. Only one wrapper creates anything:

- Encodings (plain, base64, gzip, charcode), sleep/jitter, delay and parent-process shift: no artifacts.
- AMSI patch (advanced only): changes the in-process scanning state; nothing persists past the process.
- **schtasks context**: creates the scheduled task `BAS-V-<hash>`, runs it, waits 15 seconds, then deletes it. If the agent kills the variant between create and delete, the task is left behind. This is a real artifact.

The schtasks variant gets its own cleanup check (`variant/cleanup.go`): delete the named task, then fail if it is still present. The check runs in cmd, so the PowerShell base-test cleanup cannot be used for it. Its status is **unverified**.

## Cleanup decision

- Base payload: no artifact, so no cleanup command is needed. By inspection the status would be `read_only`.
- Per your rule, that is not yet verified. The family stays `unverified`, so it is ineligible outside a lab.
- schtasks variants: cleanup written (the task check); status `unverified` until a lab run confirms it.

## Lab validation: NOT RUN

No Windows lab endpoint is available to me. Still to do, on a lab-labelled endpoint:

1. Snapshot the endpoint's files, registry run keys, services and scheduled tasks.
2. Run the base stager and confirm the snapshot is unchanged, and no `BAS-V-*` task exists.
3. Run each schtasks variant to completion; confirm no `BAS-V-*` task remains.
4. Kill a schtasks variant between create and delete; run the task check; confirm it reports the leftover and the cleanup then removes it.
5. Stop the stager at each stage (before the request, during, after) and confirm the cleanup verdict and residue.
6. Only if every check passes: set the base family to `read_only` (no artifacts) and the schtasks cleanup to `verified`.
