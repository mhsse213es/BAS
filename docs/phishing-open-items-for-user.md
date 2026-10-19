# Phishing BAS: items waiting on the user

These cannot be completed from the repository. Each needs input or access that only the user has.

1. **1.9.0 build provenance.** Needs the `verification.json` file for the 1.9.0 build.
2. **Staging database state.** Unknown whether the staging database was wiped during the earlier UFW incident. Confirm the current state before any deployment. Do not wipe it.
3. **Staging `setup.test.sh` command name.** The message was cut off, so the command name is unconfirmed. Send the full command name.

4. **Tenant-admin consent for `Policy.Read.ConditionalAccess`.** A tenant administrator must grant admin consent in Entra ID for the app registration. Needed by PH-ID-003 to read Conditional Access policies. Until granted, PH-ID-003 returns Unknown rather than Blocked, and it stays unavailable.

Explicitly excluded by the user for now: live validation and QA parts.
