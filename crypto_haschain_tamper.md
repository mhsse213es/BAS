# Cryptographic Hash Chaining for Tamper Events

## Goal
Implement a tamper-evident, cryptographically chained, append-only log for filesystem tamper events in the PostgreSQL database. This ensures that even if an operator has full administrative control over the PostgreSQL database, they cannot modify or delete tamper events (or mark them as acknowledged) without breaking the cryptographic chain and triggering a startup block.

## Design Details

### 1. Cryptographic Hash Chain Structure
Each row in the `tamper_events` table will contain:
- `chain_hash` (text): The HMAC-SHA256 signature of the current row's properties and the previous row's `chain_hash`.
- `prev_hash` (text): The `chain_hash` of the immediately preceding row. For the first row, a default seed (64 zeroes) is used.

The hash is calculated as:
`chain_hash = HMAC-SHA256(Secret, ID + DetectedAt + Path + EventType + Severity + AckedBy + PrevHash)`

To prevent database-level tampering of the "acknowledged" state, the table will be made **append-only**:
- To acknowledge an event, rather than updating `acknowledged = true` in place, the system will insert a new row of `event_type = 'acknowledge'` with `path = <target_event_id>` and `acked_by = <user_id>`.
- To find unacknowledged events, the query will check for any event (`write`, `remove`, `create`) that does not have a corresponding `acknowledge` entry.

### 2. Secret Management
The HMAC signature will be keyed using a secret derived from the existing `JWTSecret` (or a dedicated env var `TAMPER_CHAIN_SECRET` if provided). This secret is kept in the server's memory and is not stored in the database.

### 3. Startup Verification
Upon orchestrator startup, a verification routine will:
1. Fetch all rows from `tamper_events` ordered by `detected_at ASC, id ASC`.
2. Verify the hash of each row.
3. Verify that `prev_hash` matches the hash of the preceding row.
4. If the chain is broken (indicating direct database modification, deletion of a row, or unauthorized update), the orchestrator will:
   - Log a critical security alert: `[FATAL] Database integrity violation: tamper event log has been altered!`
   - Set `DispatchBlocked = true` so no agent dispatches can run.
   - Display a special "Database Integrity Alert" banner in the UI.

---

## Proposed Changes

### Database Layer
#### [MODIFY] [postgres.go](file:///c:/Users/Administrator/Downloads/Audspect_Cloud/orchestrator/internal/db/postgres.go)
- Update `EnsureSchema` to:
  - Add `prev_hash` (text) and `chain_hash` (text) columns to `tamper_events`.
  - Drop the now-redundant `acknowledged` and `acked_at` columns (or keep them but ignore them, or handle the migration cleanly).
- Add validation function `VerifyTamperChain(ctx context.Context, secret string) (bool, error)` to recalculate the chain and verify integrity.

### Watcher Layer
#### [MODIFY] [watcher.go](file:///c:/Users/Administrator/Downloads/Audspect_Cloud/orchestrator/internal/integrity/watcher.go)
- Update `recordTamper` to:
  - Fetch the last inserted event's `chain_hash` to use as `prev_hash`.
  - Calculate HMAC-SHA256 of the new row.
  - Insert the event including `prev_hash` and `chain_hash`.
- Add a global flag `DatabaseTampered atomic.Bool` to track if the startup validation failed.

### API Layer
#### [MODIFY] [tamper_handlers.go](file:///c:/Users/Administrator/Downloads/Audspect_Cloud/orchestrator/internal/api/tamper_handlers.go)
- Update `GetTamperEvents` to use the new join query to filter out acknowledged events (i.e. those with a matching `acknowledge` type row).
- Update `AcknowledgeTamperEvent` and `AcknowledgeAllTamperEvents` to perform an `INSERT` of an `acknowledge` type event instead of an `UPDATE`.
- Recalculate the hash chain during these insertions.

### Frontend
#### [MODIFY] [index.html](file:///c:/Users/Administrator/Downloads/Audspect_Cloud/orchestrator/wwwroot/index.html)
- Display a different alert banner message if `DatabaseTampered` is true (e.g. "DATABASE INTEGRITY FAULT: The tamper logs have been modified directly in the database. Run dispatching is locked.").

---

## Verification Plan

### Manual Verification
1. Run a build using `.\build.ps1`.
2. Cause a file tamper event (e.g., edit a scenario file). Verify it shows up in the UI and is stored in the DB with `prev_hash` and `chain_hash`.
3. Acknowledge it in the UI and verify that a new `acknowledge` row is appended.
4. Manuring the database: Manually log into PostgreSQL and run `DELETE` on one of the rows, or update a path name.
5. Restart the server and verify that:
   - The startup check detects the chain break.
   - The UI shows "DATABASE INTEGRITY FAULT" and blocks all dispatch buttons.
