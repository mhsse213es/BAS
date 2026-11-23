# Audit log retention

**Minimum:** 180 days (CERT-In directions; cited in the RBI CSF mapping).

**How it is enforced**
- The `audit_logs` table is append-only. The application role has `UPDATE` and `DELETE` revoked on it (`internal/db/app_role.go`). No code path deletes audit rows.
- `GET /api/audit-logs/retention` (permission `CanViewAuditLogs`) reports the age of the oldest entry and whether it meets the 180-day minimum. The check reads the database; it does not trust this document.

**Maximum retention (off by default)**
- `AUDIT_PURGE_ENABLED=true` turns on purging. Rows older than `AUDIT_PURGE_MAX_DAYS` (default 365) are removed. The maximum is never below 180 days.
- Purging runs daily as the dedicated `bas_audit_purger` role. That role has `SELECT` and `DELETE` on `audit_logs` only: no superuser, no ownership, no other tables. `bas_app` still cannot delete audit rows.
- Each batch is written to `AUDIT_ARCHIVE_DIR` as JSON Lines with a manifest. The manifest holds the cutoff, id range, row count and SHA-256, and is signed with the RSA key at `AUDIT_ARCHIVE_PRIVATE_KEY`. The archive is re-read and verified against `AUDIT_ARCHIVE_PUBLIC_KEY` before any row in it is deleted. If writing, verifying or deleting fails, the purge stops and no further rows are deleted.
- Each batch is recorded as an `audit.purge` audit entry with the cutoff, row count, archive id, and SHA-256.
- Purging stays off if any setting is missing or the keys do not match. The log says which setting is missing.
- `AUDIT_PURGE_PASSWORD` is a secret. It is never serialized.

- Raw detection alerts are pruned after `detect.RawRetentionDays`, which is set to the 180-day minimum (`internal/detect/retention.go`). The per-step results keep matched alerts indefinitely.
