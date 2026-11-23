# Browser, cloud and mailbox discovery: telemetry export

The scenario `scenarios/collection-browser-cloud-email-discovery.yaml` scores detection only
from an exported EDR/DLP event file. Discovery alone is never treated as detection.

## Setting

    BAS_EDR_EVENTS_FILE = C:\path\to\edr-events.jsonl

The file must be JSON lines, one event per line, with at least these fields:

| Field | Type | Meaning |
|---|---|---|
| `timestamp` | ISO 8601 string, with offset or UTC | When the event happened |
| `process_id` | integer | Process that touched the file |
| `file_path` | string | Full path of the file that was touched |

The correlation step matches an event when the process id equals the probe's process id,
the file name matches the probe file, and the timestamp falls within 5 seconds before to 60
seconds after the probe. Field names are fixed by this document. Export the events with your
own product's tooling, and map its field names to these before setting the variable.

## Verdicts

| Step | Verdict | Meaning |
|---|---|---|
| Correlation | PASS | An event matched the probe's process, file and time. The control detected the access. |
| Correlation | FAIL | The export is newer than the probe and holds no matching event. The access was missed. |
| Correlation | SKIP (not configured) | `BAS_EDR_EVENTS_FILE` is not set or the file does not exist. No integration on this deployment. |
| Correlation | SKIP (unverified) | The export is older than the probe or empty. Absence of an event is not evidence. |
| Correlation | ERROR | The file is not JSON lines, lacks the fields above, or the probe record is missing. |
| Integration health | PASS | The export parses and its newest event is within 24 hours. |
| Integration health | SKIP (unverified) | The export is older than 24 hours, so it cannot evidence the probes. |
| Sync-folder probe | SKIP (unverified) | Opt-in not set, a sync client is running, or no sync folder exists. Nothing was written. |
| Evidence completeness | PASS | Both probes recorded process id, UTC time and file path. |
| Evidence completeness | ERROR | A probe record is missing or incomplete. |

## What is not covered

- Sync-folder access detection runs only when `BAS_SYNC_PROBE=1` is set, no sync client process
  is running, and a sync folder exists. It writes a synthetic file in a dedicated subfolder and
  deletes it at once. Otherwise the probe reports UNVERIFIED. Set the variable only on a test host.
- Full T1619 cloud object discovery and full T1114 email collection are not claimed. The
  scenario covers local discovery only.
- No browser database, cookie, password, token, mailbox or cloud file is opened or read.
