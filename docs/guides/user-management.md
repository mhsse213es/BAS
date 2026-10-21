# Audspect BAS — User Management Guide

**Platform Version:** v1.7.3

---

## Overview

Audspect BAS uses role-based access control (RBAC) with three roles. User accounts are managed exclusively from the dashboard or API by admin-role users. There is no external identity provider integration in v1.7.3 — all accounts are local.

---

## Roles

| Role | Who Should Have It |
|---|---|
| **Viewer** | Management, auditors, read-only stakeholders |
| **Analyst** | Security operations team members who run simulations and manage findings |
| **Admin** | Platform administrators; security team leads; initial deployment owner |

### Permission matrix

| Capability | Viewer | Analyst | Admin |
|---|---|---|---|
| View agents, scenarios, runs, reports | ✓ | ✓ | ✓ |
| Download agent binaries | ✓ | ✓ | ✓ |
| View findings, remediations | ✓ | ✓ | ✓ |
| View compliance scores | ✓ | ✓ | ✓ |
| View exercise records | ✓ | ✓ | ✓ |
| Run scenarios | | ✓ | ✓ |
| Create/edit/clone scenarios | | ✓ | ✓ |
| Dispatch attack path collection | | ✓ | ✓ |
| Set finding status, add notes | | ✓ | ✓ |
| Create tickets from findings | | ✓ | ✓ |
| Create/manage campaigns | | ✓ | ✓ |
| Launch, abort and approve exercise executions | | ✓ | ✓ |
| Create/manage exercise plans | | | ✓ |
| Re-validate findings | | ✓ | ✓ |
| Trigger threat intel sync | | | ✓ |
| View agent secret (Connection Config) | | | ✓ |
| Manage users (create/edit/delete) | | | ✓ |
| Reset passwords | | | ✓ |
| Set agent lifecycle state | | | ✓ |
| Configure AP schedule | | | ✓ |
| Access audit log | | | ✓ |

---

## Creating Users

**Dashboard:** Settings → Users → Add User

**Required fields:**
- Username (use the user's email address by convention)
- Initial password (at least 8 characters)
- Role (Viewer / Analyst / Admin; defaults to Analyst if omitted)

New users receive the `must_change_pw` flag — the dashboard requires a password change at first login before the user can continue.

**API:**
```
POST /api/users
Authorization: Bearer <admin-jwt>
Body:
{
  "username": "analyst@company.com",
  "role": "analyst",
  "password": "TemporaryP@ss1!"
}
```

---

## Password Policy

| Requirement | Value |
|---|---|
| Minimum length | 8 characters (enforced by the API on create, change and reset) |
| Must contain | Not enforced by the API (length check only) |
| Algorithm | PBKDF2-HMAC-SHA256, 310,000 iterations (NIST SP 800-132) |
| Hash format | `$pbkdf2-sha256$<iter>$<salt>$<dk>` |
| Iteration count | Configurable via `BAS_PBKDF2_ITERATIONS` (minimum 310,000 enforced) |
| Self-test | Crypto self-test runs at orchestrator startup; startup aborted if self-test fails |

### Password change (user-initiated)

Users can change their own password from the dashboard (top-right menu → Change Password). They must provide their current password to set a new one.

**API:**
```
POST /api/auth/change-password
Body: { "currentPassword": "...", "newPassword": "..." }
```

### Password reset (admin)

Admins can reset any user's password without knowing the current password:

**Dashboard:** Settings → Users → [user] → Reset Password

**API:**
```
POST /api/users/{id}/reset-password
Body: { "newPassword": "..." }
```

After a reset, `must_change_pw` is re-enabled — the user must change their password on next login.

---

## First-Login Flow

On every login that has `must_change_pw = true`:

1. User submits credentials at the login form
2. Login succeeds → JWT issued
3. Dashboard redirects to a mandatory password-change form
4. The login response includes `mustChangePw`; the dashboard shows the mandatory change form. The API does not block other endpoints while the flag is set.
5. After password change → `must_change_pw` cleared → full dashboard access granted

This applies to:
- New accounts created by admin
- Any account after an admin password reset

The admin account created by `install.sh` does not have the flag set.

---

## Editing Users

Admins can change a user's role at any time:

**Dashboard:** Settings → Users → [user] → Edit Role

**API:**
```
PUT /api/users/{id}
Body: { "role": "admin" }
```

The same endpoint accepts `"isActive": true|false` (see Deactivation). Admins cannot change their own role.

Role changes take effect immediately. Active sessions (JWTs) already issued retain the old role until they expire (24-hour TTL) or until the user logs out and back in.

---

## Deactivating and Deleting Users

### Deactivation

Set `isActive` to `false` to block a user from logging in. A deactivated user receives `403 account is disabled` at login. Set it back to `true` to re-enable the account.

**API:**
```
PUT /api/users/{id}
Body: { "isActive": false }
```

You cannot deactivate your own account.

### Deletion

Permanently removes the user account. Runs, findings, and notes created by this user are retained with the user's email as a static attribution string.

**Dashboard:** Settings → Users → [user] → Delete

**API:**
```
DELETE /api/users/{id}
```

You cannot delete your own account. The server does not block deleting the last remaining admin account, so keep at least one other admin before deleting one.

---

## Audit Trail

All user management actions are written to the **Audit Log**:

| Action | Logged fields |
|---|---|
| User created | Creator email, new user email, role |
| Password changed | User email, timestamp (password itself never logged) |
| Password reset | Admin email, target user ID |
| Role changed | Admin email, target user ID (old and new role are not recorded) |
| User deleted | Admin email, deleted user ID |
| Login success | User email, IP address, timestamp |
| Login failure | Attempted email, IP address, timestamp |

The audit log is accessible to Admin users: **Audit Logs** in the sidebar, or `GET /api/audit-logs` (filters: `action`, `actor`, `limit`, `offset`; for example `GET /api/audit-logs?action=user.create`).

---

## Initial Admin Account

`install.sh --install` creates the first admin account from `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `setup.conf`. The account is created without `must_change_pw`.

The orchestrator creates an admin account at startup only when no admin account exists yet, using `BAS_ADMIN_EMAIL` and `BAS_ADMIN_PASSWORD`. An existing admin is never overwritten at startup, so a password changed in the dashboard persists across restarts.

If `BAS_ADMIN_EMAIL` is not set, the username is `admin`. If `BAS_ADMIN_PASSWORD` is not set and no admin exists, no account is created; create the first admin through the setup endpoint (`install.sh` does this). There is no built-in default password. The password must be at least 10 characters.

---

## Session Management

- JWT tokens are issued on login and expire after 24 hours
- Tokens are stored as HttpOnly, SameSite=Strict cookies — they are not readable by JavaScript
- There is no token revocation list; a logged-out user's token remains cryptographically valid until expiry
- To effectively revoke a user's session, rotate `JWT_SECRET` in `.env` and restart the orchestrator (this invalidates all active sessions for all users)

---

*© Audspect — Confidential — Customer Distribution*
