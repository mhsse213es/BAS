# Audit log retention

**Minimum:** 180 days (CERT-In directions; cited in the RBI CSF mapping).

**How it is enforced**
- The `audit_logs` table is append-only. The application role has `UPDATE` and `DELETE` revoked on it (`internal/db/app_role.go`). No code path deletes audit rows.
- `GET /api/audit-logs/retention` (permission `CanViewAuditLogs`) reports the age of the oldest entry and whether it meets the 180-day minimum. The check reads the database; it does not trust this document.

**What is not covered**
- No maximum retention is set. Audit rows are kept indefinitely. Setting a maximum would require a purge role that can delete from `audit_logs`, which weakens the append-only guarantee. That is a decision for the operator, not a default.
- Raw detection alerts are pruned after `detect.RawRetentionDays`, which is set to the 180-day minimum (`internal/detect/retention.go`). The per-step results keep matched alerts indefinitely.
