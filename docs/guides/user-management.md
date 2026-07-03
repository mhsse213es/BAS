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
| Create/manage exercises | | ✓ | ✓ |
| Re-validate findings | | ✓ | ✓ |
| Trigger threat intel sync | | ✓ | ✓ |
| View agent secret (Connection Config) | | | ✓ |
| Manage users (create/edit/delete) | | | ✓ |
| Reset passwords | | | ✓ |
| Set agent lifecycle state | | | ✓ |
| Configure AP schedule | | | ✓ |
| Delete runs, findings | | | ✓ |
| Access audit log | | | ✓ |

---

## Creating Users

**Dashboard:** Settings → Users → Add User

**Required fields:**
- Email address (used as username)
- Role (Viewer / Analyst / Admin)
- Initial password

New users receive the `must_change_pw` flag — they are forced to change their password on first login before accessing any platform feature.

**API:**
```
POST /api/users
Authorization: Bearer <admin-jwt>
Body:
{
  "email": "analyst@company.com",
  "role": "analyst",
  "password": "TemporaryP@ss1!"
}
```

---

## Password Policy

| Requirement | Value |
|---|---|
| Minimum length | 12 characters |
| Must contain | Uppercase, lowercase, digit, special character |
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
4. All API requests until password is changed return `403 Password change required`
5. After password change → `must_change_pw` cleared → full dashboard access granted

This applies to:
- New accounts created by admin
- Any account after an admin password reset
- The initial admin account on fresh deployment

---

## Editing Users

Admins can change a user's role at any time:

**Dashboard:** Settings → Users → [user] → Edit Role

**API:**
```
PUT /api/users/{id}
Body: { "role": "admin" }
```

Role changes take effect immediately. Active sessions (JWTs) already issued retain the old role until they expire (24-hour TTL) or until the user logs out and back in.

---

## Deactivating and Deleting Users

### Deactivation

There is no soft-deactivation toggle. To prevent a user from logging in, reset their password to a random string (which they don't have).

### Deletion

Permanently removes the user account. Runs, findings, and notes created by this user are retained with the user's email as a static attribution string.

**Dashboard:** Settings → Users → [user] → Delete

**API:**
```
DELETE /api/users/{id}
```

You cannot delete your own account. You cannot delete the last admin account.

---

## Audit Trail

All user management actions are written to the **Audit Log**:

| Action | Logged fields |
|---|---|
| User created | Creator email, new user email, role |
| Password changed | User email, timestamp (password itself never logged) |
| Password reset | Admin email, target user email |
| Role changed | Admin email, target user, old role, new role |
| User deleted | Admin email, deleted user email |
| Login success | User email, IP address, timestamp |
| Login failure | Attempted email, IP address, timestamp |

The audit log is accessible to Admin users: **Audit Logs** in the sidebar, or `GET /api/events?category=user`.

---

## Initial Admin Account

On first deployment, the orchestrator seeds one admin account using:
- Username: value of `BAS_ADMIN_EMAIL` environment variable
- Password: value of `BAS_ADMIN_PASSWORD` environment variable
- `must_change_pw = true`

If `BAS_ADMIN_EMAIL` is not set, the orchestrator uses `admin` as the username. If `BAS_ADMIN_PASSWORD` is not set, a random password is generated and printed once to the orchestrator container log:

```bash
docker compose logs orchestrator | grep "admin password"
```

This is a one-time operation on first run. The seed is skipped if any user already exists in the database.

---

## Session Management

- JWT tokens are issued on login and expire after 24 hours
- Tokens are stored as HttpOnly, SameSite=Strict cookies — they are not readable by JavaScript
- There is no token revocation list; a logged-out user's token remains cryptographically valid until expiry
- To effectively revoke a user's session, rotate `JWT_SECRET` in `.env` and restart the orchestrator (this invalidates all active sessions for all users)

---

*© Audspect — Confidential — Customer Distribution*
