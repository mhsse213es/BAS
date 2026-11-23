# Audit log retention

**Minimum:** 180 days (CERT-In directions; cited in the RBI CSF mapping).

**How it is enforced**
- The `audit_logs` table is append-only. The application role has `UPDATE` and `DELETE` revoked on it (`internal/db/app_role.go`). No code path deletes audit rows.
- `GET /api/audit-logs/retention` (permission `CanViewAuditLogs`) reports the age of the oldest entry and whether it meets the 180-day minimum. The check reads the database; it does not trust this document.

**What is not covered**
- No maximum retention is set. Audit rows are kept indefinitely. Setting a maximum would require a purge role that can delete from `audit_logs`, which weakens the append-only guarantee. That is a decision for the operator, not a default.
- Other log-like data is pruned on a schedule and is not covered by this policy. Raw detection blobs are pruned after 30 days (`internal/detect/retention.go`). If those count as logs for CERT-In, the 30-day prune breaks the 180-day minimum and must change first.
